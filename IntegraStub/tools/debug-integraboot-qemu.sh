#!/bin/bash
cd "$(dirname "$(dirname "$0")")"

efi_path="$(realpath "./build/debug_integraboot.efi")"
elf_path="$(realpath "./build/debug_integrastub.elf")"

mkdir -p ./build/debug_env/
mkfifo ./build/debug_env/vmserial.in ./build/debug_env/vmserial.out 1>/dev/null 2>&1
cp /usr/share/edk2/x64/OVMF_VARS.4m.fd ./build/debug_env/OVMF_VARS.fd

setsid qemu-system-x86_64 \
 -cpu qemu64 \
 -m 2G \
 -drive if=pflash,format=raw,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.4m.fd \
 -drive if=pflash,format=raw,file=./build/debug_env/OVMF_VARS.fd \
 -kernel "$efi_path" \
 -s -serial pipe:./build/debug_env/vmserial &

while read -r line; do
    if echo "$line" | grep -q "integraboot@"; then
        base_address="$(echo "$line" | sed 's/.*integraboot@//')"
        break
    fi
done <"./build/debug_env/vmserial.out"

cat >"./build/debug_env/integraboot.gdb" <<EOF
set architecture i386:x86-64
file ${efi_path}
symbol-file ${elf_path} -o ${base_address}
set var wait=0
EOF