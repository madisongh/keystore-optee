# Keystore for OP-TEE

Derived from the [Keystore](https://github.com/madisongh/keystore)
implementation for Jetson platforms with the Trusty TEE, this
is an OP-TEE Trusted App and corresponding client tool for
managing a dm-crypt/LUKS passphrase in secure storage.

The [ta](ta) subdirectory contains the code for the TA, which should
be built against the TA dev kit for the OP-TEE OS being targeted.
The OP-TEE implementation must include support for persistent object
storage.

The [ca](ca) subdirectory contains the `keystoretool` program.

* `keystoretool -p` retrieves the stored passphrase.  The TA permits
  this operation just once per system boot, so it would typically be
  used in the initrd for unlocking an encrypted rootfs filesystem. If no
  passphrase has already been stored, a new one is created using printable
  characters selected at random using `getrandom(2)`.  The passphrase
  is printed on stdout unless the `-o <FILE>` option is added.

* `keystoretool -p --force-generate`  force-generates a new
  random passphrase, erasing any existing one.  This would be used in
  an initial system setup/installation script when setting up LUKS
  partitions.  The new passphrase is printed on stdout or written to
  the file specified with the `-o <FILE>` option.

* `keystoretool -b` can be used to disable access to the passphrase
  without retrieving it.

## NOTICE

This code is provided as an example only, and comes with no warranties
or assurances as to its security or suitability for any particular purpose.
**Use at your own risk.**
