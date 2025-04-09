/*
 * SPDX-License-Identifier: MIT
 *
 * vhash-get
 *
 * Retrieves a stored verity root hash.
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
	{ "slot",		required_argument,	0, 's' },
	{ "output",             required_argument,	0, 'o' },
	{ "help",		no_argument,		0, 'h' },
	{ 0,			0,			0, 0   }
};
static const char *shortopts = ":pbgno:h";

static char *optarghelp[] = {
	"--slot               ",
	"--output             ",
	"--help               ",
};

static char *opthelp[] = {
	"select rootfs slot (0=A, 1=B)",
	"file to write the hash to instead of stdout",
	"display this help text"
};

static const ssize_t NO_PASSPHRASE = -77;


static void
print_usage (void)
{
	int i;
	printf("\nUsage:\n");
	printf("\tvhash-get <option>\n\n");
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
 * get_hash
 *
 * Retrieves a hash from the keystore.
 *
 */
static int
get_hash (FILE *outf, uint32_t hash_id)
{
	char buf[256];
	ssize_t n = -1;

	n = run_keystore_cmd(KEYSTORE_CMD_RETRIEVE, hash_id, 0,
			     buf, sizeof(buf));
	if (n < 0)
		return 1;

	fprintf(outf, "%*.*s\n", (int) n, (int) n, buf);
	return 0;

} /* get_hash */

/*
 * parse_slot
 *
 * Parses a slot identifier: 0/a/A or 1/b/B
 */
static bool
parse_slot (const char *arg, uint32_t *hash_id)
{
	if (arg == NULL || strlen(arg) != 1)
		return false;
	if (*arg == '0' || *arg == 'a' || *arg == 'A')
		*hash_id = KEYSTORE_ID_VHASH_A;
	else if (*arg == '1' || *arg == 'b' || *arg == 'B')
		*hash_id = KEYSTORE_ID_VHASH_B;
	else
		return false;
	return true;
}
/*
 * main program
 */
int
main (int argc, char * const argv[])
{
	int c, which, ret;
	char *outfile = NULL;
	FILE *outf = stdout;
	uint32_t hash_id = KEYSTORE_ID_VHASH_A;


	if (argc < 2) {
		print_usage();
		return 1;
	}

	while ((c = getopt_long_only(argc, argv, shortopts, options, &which)) != -1) {

		switch (c) {

			case 'h':
				print_usage();
				return 0;
			case 's':
				if (!parse_slot(optarg, &hash_id)) {
					fprintf(stderr, "Error: invalid slot identifier\n");
					print_usage();
					return 1;
				}
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

	if (outfile != NULL) {
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
	ret = get_hash(outf, hash_id);
	if (outf != stdout) {
		if (fclose(outf) == EOF) {
			perror(outfile);
			ret = 1;
		}
	}

	return ret;

} /* main */
