/* SPDX-License-Identifier: MIT */
#ifndef keystore___h
#define keystore___h
/* Copyright (c) 2023, M. Madison */

#define KEYSTORE_TA_UUID { 0x9610a582, 0x121e, 0x4b35, \
			   { 0x85, 0x9b, 0x13, 0x55, 0x6a, 0x93, 0x8c, 0x11 }}

typedef enum {
	/*
	 * RETRIEVE - retrieve a stored passphrase
	 * arg[0] (value-in) index of passphrase
	 * arg[1] (value-in) flags
	 * arg[2] (memref-out) output buffer for passphrase
	 * arg[3] (unused)
	 */
	KEYSTORE_CMD_RETRIEVE = 1,
	/*
	 * STORE - store a passphrase
	 * arg[0] (value-in) index of passphrase
	 * arg[1] (value-in) flags
	 * arg[2] (memref-in) buffer containing passphrase to store
	 * arg[3] (unused)
	 */
	KEYSTORE_CMD_STORE,
	/*
	 * DISABLE - disable retrieval of passphrase
	 * arg[0] (value-in) index of passphrase
	 * arg[1] (unused)
	 * arg[2] (unused)
	 * arg[3] (unused)
	 */
	KEYSTORE_CMD_DISABLE,
} keystore_cmd_t;

/*
 * The RETRIEVE command by default disables any further
 * access to the store passphrase.
 */
#define KEYSTORE_RETRIEVE_NODISABLE (1<<0)
/*
 * The STORE command by default returns an error if the
 * passphrase object has already been created
 */
#define KEYSTORE_STORE_OVERWRITE (1<<0)


/*
 * Up to 32 entries supported.
 *  0: dm-crypt passphrase
 *  1: verity root hash for rootfs A
 *  2: verity root hash for rootfs B
 */
#define KEYSTORE_ID_DMCPP	0
#define KEYSTORE_ID_VHASH_A	1
#define KEYSTORE_ID_VHASH_B	2
#define KEYSTORE_MAX_ID		31

/*
 * Maximum passphrase/key size, in bytes
 */
#define KEYSTORE_PP_MAXSIZE 64

#endif /* keystore___h */
