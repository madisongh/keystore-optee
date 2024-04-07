/*
 * SPDX-License-Identifier: MIT
 *
 * keystoretool.c
 *
 * Retrieves a passphrase from OP-TEE persistent
 * secure storage for use with dm-crypt/LUKS.
 * If the passphrase is not present in the persistent
 * store, a new, random one is generated.
 *
 * Requires the corresponding keystore TA for
 * OP-TEE, and an OP-TEE implementation that
 * includes secure storage functionality that is
 * usable from an initrd (so probably not stored
 * in the normal OS filesystem, unless you have
 * mounted the filesystem in the initrd prior to
 * invoking this tool).
 *
 * Derived from the Trusty-based implementation for
 * Tegra platforms at https://github.com/madisongh/keystore
 *
 * Copyright (c) 2019-2023, Matthew Madison.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/random.h>
#include <tee_client_api.h>
#include "keystore.h"


static struct option options[] = {
	{ "get-passphrase",	no_argument,		0, 'p' },
	{ "bootdone",		no_argument,		0, 'b' },
	{ "generate",		no_argument,		0, 'g' },
	{ "no-retry",           no_argument,            0, 'n' },
	{ "output",             required_argument,	0, 'o' },
	{ "help",		no_argument,		0, 'h' },
	{ 0,			0,			0, 0   }
};
static const char *shortopts = ":pbgno:h";

static char *optarghelp[] = {
	"--get-passphrase     ",
	"--bootdone           ",
	"--generate           ",
	"--no-retry           ",
	"--output             ",
	"--help               ",
};

static char *opthelp[] = {
	"extract the dmcrypt passphrase",
	"set booting complete",
	"force generation of new passphrase",
	"no retries on initial failure, just return error",
	"file to write the passphrase to instead of stdout",
	"display this help text"
};

static const ssize_t NO_PASSPHRASE = -77;


static void
print_usage (void)
{
	int i;
	printf("\nUsage:\n");
	printf("\tkeystoretool <option>\n\n");
	printf("Options (use only one per invocation):\n");
	for (i = 0; i < sizeof(options)/sizeof(options[0]) && options[i].name != 0; i++) {
		printf(" %s\t%c%c\t%s\n",
		       optarghelp[i],
		       (options[i].val == 0 ? ' ' : '-'),
		       (options[i].val == 0 ? ' ' : options[i].val),
		       opthelp[i]);
	}

} /* print_usage */

/*
 * initialize_secure_storage
 *
 * Rockchip-specific call to ensure that the secure storage TA is set up for
 * using the eMMC RPMB.
 */
static ssize_t
initialize_secure_storage (void)
{
	TEEC_Result result;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation oper;
	TEEC_UUID rktemp_uuid = {
		0x1b484ea5, 0x698b, 0x4142,
		{ 0x82, 0xb8, 0x3a, 0xcf, 0x16, 0xe9, 0x9e, 0x2a }
	};
	uint32_t origin;

	memset(&oper, 0, sizeof(oper));
	result = TEEC_InitializeContext(NULL, &ctx);
	if (result != TEEC_SUCCESS)
		return -1;
	oper.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					   TEEC_NONE, TEEC_NONE);
	/* 1 selects RPMB, 0 selects the 'security' partition */
	oper.params[0].value.a = 1;
	result = TEEC_OpenSession(&ctx, &sess, &rktemp_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, &oper, &origin);
	if (result != TEEC_SUCCESS)
		fprintf(stderr, "Error initializing secure storage: 0x%x (origin 0x%x)\n",
			result, origin);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	return (result == TEEC_SUCCESS) ? 0 : -1;
}
/*
 * run_keystore_cmd
 *
 * Returns special NO_PASSPHRASE value when there is no passphrase
 * stored; otherwise, returns length of passphrase, or negative
 * value on error (logging a message for the error).
 */
static ssize_t
run_keystore_cmd (keystore_cmd_t cmd, uint32_t idx, uint32_t flags, char *buf, size_t bufsize)
{
	TEEC_Result result;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation oper;
	TEEC_UUID keystore_uuid = KEYSTORE_TA_UUID;
	uint32_t origin;
	ssize_t retval;

	initialize_secure_storage();

	memset(&oper, 0, sizeof(oper));
	switch (cmd) {
		case KEYSTORE_CMD_RETRIEVE:
			oper.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
							   TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
			oper.params[0].value.a = idx;
			oper.params[1].value.a = flags;
			oper.params[2].tmpref.buffer = buf;
			oper.params[2].tmpref.size = bufsize;
			break;
		case KEYSTORE_CMD_STORE:
			oper.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
							   TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
			oper.params[0].value.a = idx;
			oper.params[1].value.a = flags;
			oper.params[2].tmpref.buffer = buf;
			oper.params[2].tmpref.size = bufsize;
			break;
		case KEYSTORE_CMD_DISABLE:
			oper.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
							   TEEC_NONE, TEEC_NONE);
			oper.params[0].value.a = idx;
			break;
		default:
			fprintf(stderr, "Unrecognized keystore command: 0x%x\n", cmd);
			return -1;
	}

	result = TEEC_InitializeContext(NULL, &ctx);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr, "Error initializing TEE client context: 0x%x\n", result);
		return -1;
	}
	result = TEEC_OpenSession(&ctx, &sess, &keystore_uuid,
				  TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
	if (result != TEEC_SUCCESS) {
		fprintf(stderr, "Error opening session to keystore TA: 0x%x (origin 0x%x)\n",
			result, origin);
		TEEC_FinalizeContext(&ctx);
		return -1;
	}
	result = TEEC_InvokeCommand(&sess, cmd, &oper, &origin);
	if (result == TEEC_ERROR_ITEM_NOT_FOUND)
		retval = NO_PASSPHRASE;
	else if (result != TEEC_SUCCESS) {
		fprintf(stderr, "Error invoking command %u: 0x%x (origin 0x%x)\n",
			cmd, result, origin);
		retval = -1;
	} else
		retval = (cmd == KEYSTORE_CMD_RETRIEVE ? oper.params[2].tmpref.size : 0);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return retval;

} /* run_keystore_cmd */

/*
 * new_passphrase
 *
 * Generates a new, random passphrase of 32 printable ASCII characters.
 *
 */
static int
new_passphrase (FILE *outf, bool force, bool skip_retries)
{
	char buf[32], readback[32];
	ssize_t n;
	uint8_t rnd;
	unsigned int i;
	uint32_t flags = (force ? KEYSTORE_STORE_OVERWRITE : 0);

	for (i = 0; i < sizeof(buf);) {
		if (getrandom(&rnd, sizeof(rnd), 0) < 0) {
			perror("getrandom");
			return 1;
		}
		rnd &= 0x7f;
		if (isgraph(rnd))
			buf[i++] = (char) rnd;
	}

	n = run_keystore_cmd(KEYSTORE_CMD_STORE, KEYSTORE_ID_DMCPP, flags,
			     buf, sizeof(buf));
	if (n < 0) {
		fprintf(stderr, "TA returned error storing passphrase");
		if (skip_retries) {
			fprintf(stderr, "\n");
			return 1;
		}
		fprintf(stderr, ", trying again\n");
		n = run_keystore_cmd(KEYSTORE_CMD_STORE, KEYSTORE_ID_DMCPP, flags,
				     buf, sizeof(buf));
		if (n < 0) {
			fprintf(stderr, "TA returned error on second try\n");
			return 1;
		}
	}
	n = run_keystore_cmd(KEYSTORE_CMD_RETRIEVE, KEYSTORE_ID_DMCPP, 0,
			     readback, sizeof(readback));
	if (n < 0) {
		if (n == NO_PASSPHRASE)
			fprintf(stderr, "Internal error: stored passphrase not found\n");
		return 1;
	}
	if ((size_t) n != sizeof(buf) || memcmp(buf, readback, sizeof(buf)) != 0) {
		fprintf(stderr, "Mismatch error reading back new passphrase\n");
		return 1;
	}

	fprintf(outf, "%*.*s\n", (int) n, (int) n, buf);
	return 0;

} /* new_passphrase */

/*
 * get_passphrase
 *
 * Retrieves a passphrase from the keystore, generating a new one if
 * not found, or if the generate parameter is true.
 *
 */
static int
get_passphrase (FILE *outf, bool generate, bool skip_retries)
{
	char buf[256];
	ssize_t n = -1;

	if (generate)
		return new_passphrase(outf, true, skip_retries);
	n = run_keystore_cmd(KEYSTORE_CMD_RETRIEVE, KEYSTORE_ID_DMCPP, 0,
			     buf, sizeof(buf));
	if (n == NO_PASSPHRASE)
		return new_passphrase(outf, false, skip_retries);
	if (n < 0)
		return 1;

	fprintf(outf, "%*.*s\n", (int) n, (int) n, buf);
	return 0;

} /* get_passphrase */

/*
 * set_bootdone
 *
 * Informs the keystore that we're done booting and it should refuse
 * any more requests for the passphrase. Only needed if we never
 * retrieve the passphrase in the first place, or if some other
 * program does a retrieval with the NO_DISABLE flag set.
 *
 */
static int
set_bootdone (void)
{
	return run_keystore_cmd(KEYSTORE_CMD_DISABLE, KEYSTORE_ID_DMCPP, 0, NULL, 0) < 0 ? 1 : 0;

} /* set_bootdone */


/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which, ret;
	char *outfile = NULL;
	FILE *outf = stdout;
	bool force_generate = false;
	bool skip_retries = false;
	enum { CMD_NONE, CMD_GET, CMD_BOOTDONE } cmd = CMD_NONE;

	if (argc < 2) {
		print_usage();
		return 1;
	}

	while ((c = getopt_long_only(argc, argv, shortopts, options, &which)) != -1) {

		switch (c) {

			case 'h':
				print_usage();
				return 0;
			case 'p':
				cmd = CMD_GET;
				break;
			case 'b':
				cmd = CMD_BOOTDONE;
				break;
			case 'g':
				force_generate = true;
				break;
			case 'n':
				skip_retries = true;
				break;
			case 'o':
				outfile = strdup(optarg);
				break;
			default:
				fprintf(stderr, "Error: unrecognized option\n");
				print_usage();
				return 1;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Error: unrecognized extra arguments\n");
		print_usage();
		return 1;
	}

	if (cmd == CMD_NONE) {
		fprintf(stderr, "No operation specified\n");
		print_usage();
		return 1;
	}

	if (outfile != NULL && cmd == CMD_GET) {
		int fd = open(outfile, O_CREAT|O_WRONLY|O_TRUNC, S_IRUSR|S_IWUSR);
		if (fd < 0) {
			perror(outfile);
			return 1;
		}
		outf = fdopen(fd, "w");
		if (outf == NULL) {
			perror(outfile);
			close(fd);
			unlink(outfile);
			return 1;
		}
	}
	switch (cmd) {
		case CMD_GET:
			ret = get_passphrase(outf, force_generate, skip_retries);
			break;
		case CMD_BOOTDONE:
			ret = set_bootdone();
			break;
		default:
			fprintf(stderr, "Internal processing error, unknown command code\n");
			ret = 2;
	}

	if (outf != stdout) {
		if (fclose(outf) == EOF) {
			perror(outfile);
			ret = 1;
		}
	}

	return ret;

} /* main */
