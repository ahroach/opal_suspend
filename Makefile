.DEFAULT_GOAL := opal_key_store

CC = gcc
LDCONFIG = /sbin/ldconfig
CP = /bin/cp

INSTALL_BIN_DIR = /usr/local/bin

CFLAGS = -Wall
LIBS = -lcrypto
PROGS = opal_key_store

opal_key_store:
	$(CC) $(CFLAGS) -o opal_key_store opal_key_store.c $(LIBS)

install:
	$(CP) opal_key_store $(INSTALL_BIN_DIR)

.PHONY: clean

clean:
	$(RM) $(PROGS) gmon.{out,sum} *.o *.s *~ core core.[0-9]*[0-9]

