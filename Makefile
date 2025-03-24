PHONY := all package clean push

CC := arm-vita-eabi-gcc
CXX := arm-vita-eabi-g++
STRIP := arm-vita-eabi-strip

CFLAGS += -Wl,-q -nostdlib

SRC_COMMON := tai.c patch.c inject.c
SRC_LIBSSL_KEYLOG := $(SRC_COMMON) tls-keylog.c main-libssl-keylog.c
SRC_PSN_REDIRECT := $(SRC_COMMON) http-rewrite.c xmpp-rewrite.c main-psn-redirect.c

LIBS_KERNEL += \
	-ltaihenForKernel_stub -ltaihenModuleUtils_stub \
	-lSceDebugForDriver_stub \
	-lSceIofilemgrForDriver_stub -lSceThreadmgrForDriver_stub \
	-lSceSysmemForDriver_stub  -lSceSysclibForDriver_stub \
	-lSceModulemgrForDriver_stub -lSceNetPsForDriver_stub

all: libssl-keylog.skprx psn-redirect.skprx

%.skprx: %.velf
	vita-make-fself -c -e libssl-keylog.yml $< $@

%.velf: %.elf
	$(STRIP) -g $<
	vita-elf-create $< $@

libssl-keylog.elf: $(SRC_LIBSSL_KEYLOG:.c=.o)
	$(CC) $(CFLAGS) $^ $(LIBS_KERNEL) -o $@

psn-redirect.elf: $(SRC_PSN_REDIRECT:.c=.o)
	$(CC) $(CFLAGS) $^ $(LIBS_KERNEL) -lSceSysrootForDriver_stub -o $@

inject.h: injects.py
	python injects.py

clean:
	rm -f psn-redirect.elf psn-redirect.skprx
	rm -f libssl-keylog.elf libssl-keylog.velf libssl-keylog.skprx
	rm -f $(SRC_LIBSSL_KEYLOG:.c=.o)
	rm -f $(SRC_PACKET_CAPTURE:.c=.o)
	rm -f $(SRC_PSN_REDIRECT:.c=.o)

push: $(PROJECT).skprx
	curl -T $(PROJECT).skprx ftp://${VITAIP}:1337/ur0:/tai/
	sleep 0.2
	echo reboot | nc ${VITAIP} 1338
