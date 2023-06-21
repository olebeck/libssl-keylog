PHONY := all package clean push

CC := arm-vita-eabi-gcc
CXX := arm-vita-eabi-g++
STRIP := arm-vita-eabi-strip

PROJECT := libssl-keylog
CFLAGS += -Wl,-q -nostdlib


SRC_KERNEL := kernel.c
OBJ_KERNEL_DIRS := $(dir $(SRC_KERNEL:%.c=out/%.o))
OBJS_KERNEL := $(SRC_KERNEL:%.c=out/%.o)

LIBS_KERNEL += \
	-ltaihenForKernel_stub -lSceDebugForDriver_stub \
	-lSceIofilemgrForDriver_stub -lSceThreadmgrForDriver_stub \
	-lSceModulemgrForKernel_stub -lSceModulemgrForDriver_stub \
	-lSceSysmemForDriver_stub 


all: package

package: $(PROJECT).skprx


$(PROJECT).skprx: $(PROJECT)-kernel.velf
	vita-make-fself -c -e kernel.yml $< $@

%.velf: %.elf
	$(STRIP) -g $<
	vita-elf-create $< $@

$(PROJECT)-kernel.elf: $(OBJS_KERNEL)
	$(CC) $(CFLAGS) $^ $(LIBS_KERNEL) -o $@


$(OBJ_KERNEL_DIRS):
	mkdir -p $@

out/%.o : %.c | $(OBJ_KERNEL_DIRS)
	$(CC) -c $(CFLAGS) -o $@ $<




inject.o: inject.s
	arm-vita-eabi-as $^ -o $@

inject.bin: inject.o
	arm-vita-eabi-objcopy -O binary $^ $@

inject.txt: inject.o
	arm-vita-eabi-objdump -d --adjust-vma=0x81012a6c -marm -Mforce-thumb  $^ > $@




clean:
	rm -f $(PROJECT)-kernel.velf $(PROJECT)-kernel.elf $(PROJECT).skprx $(OBJS_KERNEL)
	rm -r $(abspath $(OBJ_KERNEL_DIRS))


push: $(PROJECT).skprx
	curl -T $(PROJECT).skprx ftp://${VITAIP}:1337/ur0:/tai/
	sleep 0.2
	echo reboot | nc ${VITAIP} 1338
