/*
 * Compile with -lcrypto
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <sys/ioctl.h>
#include <linux/nvme_ioctl.h>
#include <linux/sed-opal.h>

// See sedutil source: Common/DtaHashPwd.cpp
// SHA1 HMAC used
// Salted with first 20 bytes of serial number
// From DtaHashPwd.h : dfeault iter = 75000,
// hashsize = 32


void hexdump(uint8_t *buf, int buflen)
{
	for (int i = 0; i < buflen; i++) {
		printf("%02hhx", buf[i]);
	}
	printf("\n");
}

static unsigned char *get_device_sn(const char *device)
{
	// See linux/nvme_ioct.h
	// struct nvme_admin_cmd alias for struct nvme_passthru_cmd
	struct nvme_admin_cmd id_cmd;
	uint8_t *id_res;
	unsigned char *sn;
	int fd;
	
	id_res = malloc(4096);
	if (id_res == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	memset(&id_cmd, 0, sizeof(id_cmd));
	// See NVM Express specification
	// Rev. 1.3a, Section 5.15 Identify command
	id_cmd.opcode = 0x06;
	id_cmd.nsid = 0;
	id_cmd.addr = (uint64_t)id_res;
	id_cmd.data_len = 4096;
	// Return Identify Controller data structure
	id_cmd.cdw10 = 1;

	fd = open(device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open() on %s: %s\n", device, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &id_cmd)) {
		fprintf(stderr, "Error in IDENTIFY\n");
		exit(EXIT_FAILURE);
	}

	close(fd);
	
	sn = malloc(20);
	if (sn == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	// Serial number: 20 bytes starting at offset 0x4
	memcpy(sn, id_res + 4, 20);

	free(id_res);
	return sn;
}

static unsigned char *sedutil_pbkdf2(char *device, unsigned char *pass)
{
	unsigned char *out;
	char *sn;
	// Parameters as used in the sedutil PBKDF2 implementation
	int ret, keylen = 32, passlen=-1, saltlen=20, iters=75000;

	out = malloc(keylen);
	if (out == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

	// Device serial number used as 20-byte salt for the PBKDF2
	sn = get_device_sn(device);

	ret = PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, sn, saltlen, iters,
	                             keylen, out);
	if (ret == 0) {
		fprintf(stderr, "Error in PKCS5_PBKDFS_HMAC_SHA1()\n");
		exit(EXIT_FAILURE);
	}

	free(sn);

	return out;
}

char *get_password(void) {
	char *password;
	size_t n;
	int passlen;
	struct termios tp_orig, tp_mod;

	// Disable terminal echoing for password input
	tcgetattr(1, &tp_orig);
	tp_mod = tp_orig;
	tp_mod.c_lflag &= ~ECHO;
	tp_mod.c_lflag |= (ECHONL | ICANON);
	tcsetattr(1, TCSADRAIN, &tp_mod);

	printf("Password: ");
	password = NULL;
	n = 0;
	passlen = getline(&password, &n, stdin);

	// Reset terminal attributes
	tcsetattr(1, TCSADRAIN, &tp_orig);
	
	if (passlen == -1) {
		fprintf(stderr, "Error reading password\n");
		exit(EXIT_FAILURE);
	}

	// Discard newlines
	if (password[passlen-1] == '\n') {
		password[passlen-1] = 0;
	}

	return password;
}

int opal_unlock(char *device, unsigned char *key)
{
	// That the device *must* point to the namespace
	// (for example /dev/nvme0n1), rather than the higher level
	// /dev/nvme0. If not, the ioctl will fail with
	// "Inappropriate ioctl for device"
	//
	int fd;
	// Defined in linux/sed-opal.h
	struct opal_lock_unlock opal_lu;

	memset(&opal_lu, 0, sizeof(opal_lu));
	opal_lu.session.sum = 0; // Not in single-user mode
	opal_lu.session.who = OPAL_ADMIN1;
	opal_lu.session.opal_key.lr = 0; // Locking range 0
	opal_lu.session.opal_key.key_len = 32;
	memcpy(opal_lu.session.opal_key.key, key, 32);
	opal_lu.l_state = OPAL_RW;

	fd = open(device, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open() on %s: %s\n", device, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (ioctl(fd, IOC_OPAL_LOCK_UNLOCK, &opal_lu)) {
		fprintf(stderr, "ioctl IOC_OPAL_LOCK_UNLOCK on %s: %s\n",
		        device, strerror(errno));
		exit(EXIT_FAILURE);
	}

	close(fd);

	return 0;
}

int opal_save(char *device, unsigned char *key)
{
	// That the device *must* point to the namespace
	// (for example /dev/nvme0n1), rather than the higher level
	// /dev/nvme0. If not, the ioctl will fail with
	// "Inappropriate ioctl for device"
	//
	int fd;
	// Defined in linux/sed-opal.h
	struct opal_lock_unlock opal_lu;

	memset(&opal_lu, 0, sizeof(opal_lu));
	opal_lu.session.sum = 0; // Not in single-user mode
	opal_lu.session.who = OPAL_ADMIN1;
	opal_lu.session.opal_key.lr = 0; // Locking range 0
	opal_lu.session.opal_key.key_len = 32;
	memcpy(opal_lu.session.opal_key.key, key, 32);
	opal_lu.l_state = OPAL_RW;

	fd = open(device, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open() on %s: %s\n", device, strerror(errno));
		exit(EXIT_FAILURE);
	}
	if (ioctl(fd, IOC_OPAL_SAVE, &opal_lu)) {
		fprintf(stderr, "ioctl IOC_OPAL_SAVE on %s: %s\n",
		        device, strerror(errno));
		exit(EXIT_FAILURE);
	}
	printf("Issued IOC_OPAL_SAVE\n");

	close(fd);

	return 0;
}

int main (int argc, char **argv) {
	char *device, *password; 
	unsigned char *key;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s device\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	device= argv[1];

	password = get_password();
	key = sedutil_pbkdf2(device, password);
	memset(password, 0, strlen(password));
	free(password);

	hexdump(key, 32);

	// We already unlocked when we booted. But we issue another unlock just
	// to verify that we have the correct key.
	opal_unlock(device, key);
	opal_save(device, key);

	free(key);

	return 0;
}

