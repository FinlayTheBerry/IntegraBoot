CFLAGS := -mpopcnt -fvisibility=hidden -fdiagnostics-color=always -D_FILE_OFFSET_BITS=64 -Wall -Winvalid-pch -Wextra -std=gnu17 -g -Wno-missing-field-initializers -Wno-unused-parameter -Wno-nonnull-compare -Warray-bounds -Warray-bounds=2 -Wdate-time -Wendif-labels -Werror=bool-compare -Werror=discarded-qualifiers -Werror=flex-array-member-not-at-end -Werror=format=2 -Werror=format-signedness -Werror=implicit-function-declaration -Werror=implicit-int -Werror=incompatible-pointer-types -Werror=int-conversion -Werror=missing-declarations -Werror=missing-parameter-name -Werror=missing-prototypes -Werror=overflow -Werror=override-init -Werror=pointer-sign -Werror=return-type -Werror=sequence-point -Werror=shift-count-overflow -Werror=shift-overflow=2 -Werror=strict-flex-arrays -Werror=undef -Wfloat-equal -Wimplicit-fallthrough=5 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wmissing-noreturn -Wnested-externs -Wold-style-definition -Wpointer-arith -Wredundant-decls -Wshadow -Wstrict-aliasing=2 -Wstrict-prototypes -Wsuggest-attribute=noreturn -Wunterminated-string-initialization -Wunused-function -Wwrite-strings -Wzero-as-null-pointer-constant -Wzero-length-bounds -fdiagnostics-show-option -fno-common -fstack-protector -fstack-protector-strong -fstrict-flex-arrays=3 --param=ssp-buffer-size=4 -Wno-unused-result -Werror=shadow -fPIC -DSD_BOOT=1 -ffreestanding -fno-strict-aliasing -fshort-wchar -fwide-exec-charset=UCS2 -maccumulate-outgoing-args -mstack-protector-guard=global -fcf-protection=none -fno-asynchronous-unwind-tables -fno-exceptions -fno-unwind-tables -fno-sanitize=all '-DEFI_MACHINE_TYPE_NAME="x64"' -m64 -march=x86-64 -mno-red-zone -mgeneral-regs-only
DEBUG_CFLAGS := -DEFI_DEBUG -O0
RELEASE_CFLAGS := -Wno-maybe-uninitialized -ftrivial-auto-var-init=zero -Os
LDFLAGS := -Wl,--as-needed -Wl,--no-undefined -pie -fstack-protector -Wl,--start-group -nostdlib -static-pie -Wl,--entry=efi_main -Wl,--fatal-warnings -Wl,-static,-pie,--no-dynamic-linker,-z,text -z common-page-size=4096 -z max-page-size=4096 -z noexecstack -z relro -z separate-code -Wl,--end-group -Wl,-z,nopack-relative-relocs -fcf-protection=none -fno-asynchronous-unwind-tables -fno-exceptions -fno-unwind-tables -fno-sanitize=all -m64 -lgcc
E2EFLAGS := --version-major=260 --version-minor=0 --efi-major=1 --efi-minor=1 --subsystem=10 --minimum-sections=120 --copy-sections=.sbat,.sdmagic,.osrel
INCLUDES := -Isrc/build -Isrc/fundamental -Isrc/boot -include efi-config.h
SRCS := $(shell find src -type f -name "*.c")
RELEASE_OBJS := $(patsubst src/%.c, build/release_obj/%.o, $(SRCS))
DEBUG_OBJS := $(patsubst src/%.c, build/debug_obj/%.o, $(SRCS))

release: ./build/integrastub.efi
debug: ./build/debug_integraboot.efi

./build/debug_integraboot.efi: ./build/debug_integrastub.efi ./build/mini_initrd.img ./Makefile
	ukify build --linux "$(shell find /usr/lib/modules/*/vmlinuz)" --initrd ./build/mini_initrd.img --stub ./build/debug_integrastub.efi --output $@

./build/mini_initrd.img: ./Makefile
	rm -rf ./build/mini_initrd
	mkdir -p ./build/mini_initrd
	printf "#!/ash\necho \"Mini InitRD booted successfully!\"\nwhile [ 1==1 ]; do :; done" > "./build/mini_initrd/init"
	chmod 755 ./build/mini_initrd/init
	cp "$(shell which busybox)" ./build/mini_initrd/busybox
	ln -s busybox ./build/mini_initrd/ash
	sh -c 'cd ./build/mini_initrd && find . | cpio -ov --format=newc --owner=+0:+0 --file=../mini_initrd.img'

./build/integrastub.efi: ./build/integrastub.elf ./Makefile
	@mkdir -p ./build
	tools/elf2efi.py $(E2EFLAGS) $< $@

./build/debug_integrastub.efi: ./build/debug_integrastub.elf ./Makefile
	@mkdir -p ./build
	./tools/elf2efi.py $(E2EFLAGS) $< $@

./build/integrastub.elf: $(RELEASE_OBJS) ./Makefile
	@mkdir -p ./build
	$(CC) $(LDFLAGS) -o $@ $(RELEASE_OBJS)

./build/debug_integrastub.elf: $(DEBUG_OBJS) ./Makefile
	@mkdir -p ./build
	$(CC) $(LDFLAGS) -o $@ $(DEBUG_OBJS)

./build/release_obj/%.o: ./src/%.c ./Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(RELEASE_CFLAGS) $(INCLUDES) -c $< -o $@

./build/debug_obj/%.o: ./src/%.c ./Makefile
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(DEBUG_CFLAGS) $(INCLUDES) -c $< -o $@

install: ./build/integrastub.efi ./Makefile
	install -o 0 -g 0 -m600 -D ./build/integrastub.efi /var/lib/integraboot/integrastub.efi

clean:
	rm -rf ./build

.PHONY: release debug clean