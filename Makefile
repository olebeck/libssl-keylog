PHONY := all package clean push

CC := arm-vita-eabi-gcc
CXX := arm-vita-eabi-g++
STRIP := arm-vita-eabi-strip

PROJECT := libssl-keylog
CFLAGS += -Wl,-q -nostdlib


SRC_KERNEL := kernel.c tai.c
OBJS_KERNEL := kernel.o tai.o
OBJS_KERNEL_363 := kernel.o tai-363.o

LIBS_KERNEL += \
	-ltaihenForKernel_stub -lSceDebugForDriver_stub \
	-lSceIofilemgrForDriver_stub -lSceThreadmgrForDriver_stub \
	-lSceSysmemForDriver_stub  -lSceSysclibForDriver_stub \
	-lSceModulemgrForDriver_stub


all: package

package: $(PROJECT).skprx $(PROJECT)-363.skprx


%.skprx: %.velf
	vita-make-fself -c -e kernel.yml $< $@

%.velf: %.elf
	$(STRIP) -g $<
	vita-elf-create $< $@

$(PROJECT).elf: $(OBJS_KERNEL)
	$(CC) $(CFLAGS) $^ $(LIBS_KERNEL) -lSceModulemgrForKernel_stub -o $@

$(PROJECT)-363.elf: $(OBJS_KERNEL_363)
	$(CC) $(CFLAGS) $^ $(LIBS_KERNEL) -lSceModulemgrForKernel_363_stub -o $@

%.o : %.c | $(OBJ_KERNEL_DIRS)
	$(CC) -c $(CFLAGS) -o $@ $<

%-363.o : %.c | $(OBJ_KERNEL_DIRS)
	$(CC) -c $(CFLAGS) -DVER_363 -o $@ $<



clean:
	rm -f $(PROJECT).velf $(PROJECT).elf $(PROJECT).skprx \
		  $(PROJECT)-363.velf $(PROJECT)-363.elf $(PROJECT)-363.skprx \
		  $(OBJS_KERNEL) tai-363.o


push: $(PROJECT).skprx
	curl -T $(PROJECT).skprx ftp://${VITAIP}:1337/ur0:/tai/
	sleep 0.2
	echo reboot | nc ${VITAIP} 1338
