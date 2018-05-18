/*
 * Pass the drive unlock credential to the Linux kernel to be used after
 * system resume
 *
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

static void show_help(char **argv)
{
	fprintf(stderr, "Usage: %s [-h] [-n] [-p] [-x hexstring] device\n",
	        argv[0]);
	fprintf(stderr,
		" -h  Show help\n"
	        " -n  Don't hash password\n"
	        " -p  Print hexstring of key\n"
	        " -x  Provide 32-byte key hexstring; No password prompt\n");
	exit(EXIT_FAILURE);
}

static void clear_and_free(void *buf, size_t buflen)
{
	memset(buf, 0, buflen);
	free(buf);
}

static void print_hexstring(const unsigned char *buf, size_t buflen)
{
	for (int i = 0; i < buflen; i++) {
		printf("%02hhx", buf[i]);
	}
	printf("\n");
}

static unsigned char *convert_hexstring(const char *hs, size_t len)
{
	unsigned char *out;
	int n;

	if (strlen(hs) < len*2) {
		fprintf(stderr, "Hex string is too short.\n");
		fprintf(stderr, "Expected %d bytes.\n", (int)len);
		return NULL;
	}

	if (strlen(hs) > len*2) {
		fprintf(stderr, "Hex string longer than allowed.\n");
		fprintf(stderr, "Truncating to %d bytes.\n", (int)len);
	}

	out = malloc(len);
	if (out == NULL) {
		perror("malloc");
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		n = sscanf(hs + i*2, "%02hhx", out + i);
		if (n != 1) {
			fprintf(stderr, "Error parsing hex string\n");
			free(out);
			return NULL;
		}
	}

	return out;
}

/*
 * Get user password from the terminal
 */
static char *get_password(void) {
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

	printf("Enter drive lock password: ");
	password = NULL;
	n = 0;
	passlen = getline(&password, &n, stdin);
	if (passlen == -1) {
		perror("getline()");
		if (password) free(password);
		tcsetattr(1, TCSADRAIN, &tp_orig);
		return NULL;
	}

	// Restore terminal parameters
	tcsetattr(1, TCSADRAIN, &tp_orig);

	// Discard newline
	if (password[passlen-1] == '\n') password[passlen-1] = 0;

	return password;
}

/*
 * Get device serial number using the NVME_IOCTL_ADMIN_CMD ioctl
 * See linux/nvme_ioctl.h.
 * Note that struct nvme_admin_cmd is an alias for struct nvme_passthru_cmd.
 * Command parameters (opcode, nsid, addr, data_len, cdw10) defined in the
 * NVM Express spec. In Rev. 1.3a, see Section 5.15: Identify Command
 */
static unsigned char *get_device_sn(const char *device)
{
	struct nvme_admin_cmd id_cmd;
	unsigned char *id_ctrlr_ds, *sn;
	int fd;
	
	id_ctrlr_ds = malloc(4096);
	if (id_ctrlr_ds == NULL) {
		perror("malloc");
		return NULL;
	}

	// Unused fields will be set to zero
	memset(&id_cmd, 0, sizeof(id_cmd));

	id_cmd.opcode = 0x06;
	id_cmd.nsid = 0;
	id_cmd.addr = (uint64_t)id_ctrlr_ds;
	id_cmd.data_len = 4096;
	id_cmd.cdw10 = 1; // Return Identify Controller data structure

	fd = open(device, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open(%s, O_RDONLY): %s\n",
		        device, strerror(errno));
		free(id_ctrlr_ds);
		return NULL;
	}
	if (ioctl(fd, NVME_IOCTL_ADMIN_CMD, &id_cmd)) {
		perror("NVME_IOCTL_ADMIN_CMD ioctl:");
		free(id_ctrlr_ds);
		close(fd);
		return NULL;
	}
	close(fd);
	
	sn = malloc(20);
	if (sn == NULL) {
		perror("malloc");
		free(id_ctrlr_ds);
		return NULL;
	}

	// Serial number: 20 bytes stored at offset 0x4
	memcpy(sn, id_ctrlr_ds + 4, 20);

	free(id_ctrlr_ds);
	return sn;
}

/*
 * Calls PBKDF2 in the sammer manner as sedutil to generate key from the
 * user-provided password. See sedutil source: Common/DtaHashPwd.cpp
 * Pseudo-random function: SHA1-HMAC
 * Password length: string length of provided password
 * Salt: Drive serial number (20 bytes)
 * Iters: 75000; Derived key length 32 bytes
 */
static unsigned char *sedutil_pbkdf2(const char *device, const char *pass)
{
	unsigned char *sn, *dk;
	int keylen = 32, passlen=-1, saltlen=20, iters=75000;

	sn = get_device_sn(device);
	if (sn == NULL) {
		fprintf(stderr, "Error finding serial number for %s\n",
		        device);
		return NULL;
	}

	dk = malloc(keylen);
	if (dk == NULL) {
		perror("malloc");
		free(sn);
		return NULL;
	}

	if (PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, sn, saltlen, iters,
	                           keylen, dk) == 0) {
		fprintf(stderr, "Error in PKCS5_PBKDFS_HMAC_SHA1()\n");
		free(sn);
		free(dk);
		return NULL;
	}

	free(sn);
	return dk;
}

/*
 * Generate the struct opal_lock_unlock used by both the IOC_OPAL_LOCK_UNLOCK
 * ioctl and the IOC_OPAL_SAVE ioctl. The structure and substructures are
 * defined in linux/sed-opal.h
 */
static struct opal_lock_unlock *gen_opal_lu(const unsigned char *key)
{
	struct opal_lock_unlock *opal_lu;

	opal_lu = malloc(sizeof(struct opal_lock_unlock));
	if (opal_lu == NULL) {
		perror("malloc");
		return NULL;
	}
	memset(opal_lu, 0, sizeof(struct opal_lock_unlock));
	opal_lu->session.sum = 0; // Not in single-user mode
	opal_lu->session.who = OPAL_ADMIN1;
	opal_lu->session.opal_key.lr = 0; // Locking range 0
	opal_lu->session.opal_key.key_len = 32;
	memcpy(opal_lu->session.opal_key.key, key, 32);
	opal_lu->l_state = OPAL_RW;

	return opal_lu;
}

/*
 * Issue an IOCTL that uses a struct opal_lock_unlock.  See linux/sed-opal.h.
 * Both IOC_OPAL_SAVE and IOC_OPAL_LOCK_UNLOCK use the same structure.
 *
 * Note that the device name must correspond to the *namespace* of the device
 * that you want to operate on ("/dev/nvme0n1", for example, rather than
 * "/dev/nvme0"). Otherwise, the ioctl will likely fail with "Inappropriate
 * ioctl for device.)
 */
static int opal_lu_ioctl(unsigned long request, const char *device,
                         const struct opal_lock_unlock *opal_lu)
{
	int fd;

	fd = open(device, O_WRONLY);
	if (fd < 0) {
		fprintf(stderr, "open() on %s: %s\n", device, strerror(errno));
		return 1;
	}

	if (ioctl(fd, request, opal_lu)) {
		fprintf(stderr, "ioctl %lu on %s: %s\n",
		        request, device, strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}

int main (int argc, char **argv)
{
	int opt, print_key = 0, hex_input = 0, no_hash = 0;
	char *device, *password; 
	unsigned char *key;
	struct opal_lock_unlock *opal_lu;

	while ((opt = getopt(argc, argv, "hnpx:")) != -1) {
		switch (opt) {
			case 'h':
				show_help(argv);
				break;
			case 'n':
				no_hash = 1;
				break;
			case 'p':
				print_key = 1;
				break;
			case 'x':
				hex_input = 1;
				// Checked for successful return after
				// other key generation steps below
				key = convert_hexstring(optarg, 32);
				break;
			default:
				show_help(argv);
		}
	}

	// Only regmaining argument should be the device name
	if ((argc - optind) != 1) show_help(argv);
	device = argv[optind];

	// Key can come from three sources:
	// 1. Hexstring from the command-line option, parsed above
	// 2. Direct copy of input password (no hashing)
	// 3. PBKDF2 (in the style of sedutil) applied to input password
	if (!hex_input) {
		password = get_password();
		if (password == NULL) {
			fprintf(stderr, "Failed to read password\n");
			exit(EXIT_FAILURE);
		}
		if (no_hash) {
			key = calloc(32, 1);
			if (key) strncpy((char *)key, password, 32);
		} else {
			key = sedutil_pbkdf2(device, password);
		}
		clear_and_free(password, strlen(password));
	}
	if (key == NULL) {
		fprintf(stderr, "Failed to generate key\n");
		exit(EXIT_FAILURE);
	}

	if (print_key) {
		printf("Key: ");
		print_hexstring(key, 32);
	}

	opal_lu = gen_opal_lu(key);
	clear_and_free(key, 32);
	if (opal_lu == NULL) {
		fprintf(stderr,
		        "Failed to generate struct opal_lock_unlock\n");
		exit(EXIT_FAILURE);
	}

	// If you provide the incorrect keythrough the IOC_OPAL_SAVE ioctl,
	// there is no feedback. Instead, your machine just stops working while
	// trying to return from suspend. But the IOC_OPAL_LOCK_UNLOCK ioctl
	// *does* report failure when provided an incorrect key. So we'll try
	// to unlock with the provided key, even though the range was already
	// unlocked during boot, and notify if this ioctl fails.
	if (opal_lu_ioctl(IOC_OPAL_LOCK_UNLOCK, device, opal_lu)) {
		fprintf(stderr, "Unlock failed. Incorrect password?\n");
		exit(EXIT_FAILURE);
	}
	if (opal_lu_ioctl(IOC_OPAL_SAVE, device, opal_lu)) {
		fprintf(stderr, "Failed to save credential.\n");
		exit(EXIT_FAILURE);
	}

	clear_and_free(opal_lu, sizeof(struct opal_lock_unlock));
	return 0;
}

