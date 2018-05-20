.DEFAULT_GOAL := opal_key_save

CC = gcc
LDCONFIG = /sbin/ldconfig
CP = /bin/cp

INSTALL_BIN_DIR = /usr/local/sbin

CFLAGS = -Wall
LIBS = -lcrypto
PROGS = opal_key_save

opal_key_save:
	$(CC) $(CFLAGS) -o opal_key_save opal_key_save.c $(LIBS)

install:
	$(CP) opal_key_save $(INSTALL_BIN_DIR)
	$(CP) opal_suspend_enable $(INSTALL_BIN_DIR)
	$(CP) systemd-suspend.service /etc/systemd/system

uninstall:
	$(RM) $(INSTALL_BIN_DIR)/opal_key_save
	$(RM) $(INSTALL_BIN_DIR)/opal_suspend_enable
	$(RM) /etc/systemd/system/systemd-suspend.service

.PHONY: clean

clean:
	$(RM) $(PROGS) gmon.{out,sum} *.o *.s *~ core core.[0-9]*[0-9]

