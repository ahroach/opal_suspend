.DEFAULT_GOAL := linux_key_escrow

CC = gcc
LDCONFIG = /sbin/ldconfig
CP = /bin/cp

INSTALL_BIN_DIR = /usr/local/bin

CFLAGS = -Wall
LIBS = -lcrypto
PROGS = linux_key_escrow

linux_key_escrow:
	$(CC) $(CFLAGS) -o linux_key_escrow linux_key_escrow.c $(LIBS)

install:
	$(CP) linux_key_escrow $(INSTALL_BIN_DIR)

.PHONY: clean

clean:
	$(RM) $(PROGS) gmon.{out,sum} *.o *.s *~ core core.[0-9]*[0-9]

