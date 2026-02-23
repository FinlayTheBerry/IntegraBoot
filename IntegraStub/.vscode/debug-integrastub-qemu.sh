#!/bin/bash
cd "$(dirname "$(dirname "$0")")"

make debug

mkdir -p ./obj/debug_env/
mkfifo ./obj/debug_env/integrastub.in ./obj/debug_env/integrastub.out
cp /usr/share/edk2/x64/OVMF_VARS.4m.fd ./obj/debug_env/OVMF_VARS.fd

setsid qemu-system-x86_64 \
 -cpu qemu64 \
 -m 2G \
 -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
 -drive if=pflash,format=raw,file=./obj/debug_env/OVMF_VARS.fd \
 -kernel ./bin/debug_integrastub.efi \
 -s -serial pipe:./obj/debug_env/integrastub &

efi_path="$(realpath "./bin/debug_integrastub.efi")"
elf_path="$(realpath "./obj/debug/integrastub.elf")"

while read -r line; do
    if echo "$line" | grep -q "integrastub@"; then
        base_address="$(echo "$line" | sed 's/.*integrastub@//')"
        break
    fi
done <"./obj/debug_env/integrastub.out"

cat >"./obj/debug_env/integrastub.gdb" <<EOF
set architecture i386:x86-64
file ${efi_path}
symbol-file ${elf_path} -o ${base_address}
set var wait=0
EOF