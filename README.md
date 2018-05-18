opal\_key\_store: Store TCG OPAL key in Linux kernel
====================================================

The TCG OPAL encryption standard, used in many self encrypting drives (SEDs),
can create problems when used in conjunction with suspend-to-RAM. When the
drive is unlocked at boot time, the key is acquired by the Pre-Boot
Authentication (PBA) image, supplied to the drive, and immediately discarded
when the system reboots to load the full operating system. Neither the BIOS
nor the operating system have access to the key.

The key is required to unlock the drive after each power cycle of the drive.
When a system enters the suspend-to-RAM state, the drive is powered off. When
the system resumes from the suspend-to-RAM state, the SED implementing TCG
OPAL will be in a locked state. Neither the BIOS nor the operating system
have the key to unlock it.

Since approximately Linux kernel version 4.11, a mechanism has been available
through ioctls to provide the key to the Linux kernel, to be used when the
kernel resumes from suspend. This is an implementation of userspace tools to
pass the key through the provided ioctls.

Features
--------

* Calls PBKDF2 with the same parameters as sedutil, to allow a user to input
  the same password that they would input to sedutil's PBA
* Option to directly supply key as command-line argument, encoded as a
  hexstring
* Optionally prints out key, to allow saving hexstring of PBKDF2-derived key
  for later re-use

Installation
------------

opal\_key\_store is linked against OpenSSL's libcrypto, which provides the
PBKDF2 implementation. It also requires the Linux nvme\_ioctl.h and 
sed-opal.h header files.

To build:

	make

To install:

	make install

Usage
-----

The user runs:

	opal_key_store [-h] [-n] [-p] [-x hexstring] device

with the command-line arguments:

* `-h`: show help
* `-n`: don't hash password
* `-p`: print hexstring of key
* `-x`: provide 32-byte key hexstring; no prompt for password

As an example of typical invocation, using `sedutil`'s parameters for PBKDF2
to hash the input password:

	opal_key_store /dev/nvme0n1

To view the key that is provided to the drive:

	opal_key_store -p /dev/nvme0n1

To pass a password in the clear to the drive, without hashing:

	opal_key_store -n /dev/nvme0n1

And to pass a binary key directly to the drive:

	opal_key_store -x 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff /dev/nvme0n1

Limitations
-----------

This implementation makes several assumptions about the operating environment:

* There is a single Locking Range, number 0
* The user will be providing the ADMIN1 password
* The key length is 32 bytes
* Any hashing is done using the same method as `sedutil`

It would be easy to make modifications to the code to accommodate scenarios
where these assumptions are violated. But there are no accommodations currently
in the form of command-line arguments.

References
----------

* linux/nvme\_ioctl.h
* linux/sed-opal.h
* NVM Express specification

