#!/bin/sh
cd "$(dirname "$(dirname "$0")")"

efi_path="$(realpath "./build/debug_integraboot.efi")"
elf_path="$(realpath "./build/debug_integrastub.elf")"

mkdir -p ./build/debug_env/
mkfifo ./build/debug_env/vmserial.in ./build/debug_env/vmserial.out 1>/dev/null 2>&1
cp -n /usr/share/edk2/x64/OVMF_VARS.4m.fd ./build/debug_env/OVMF_VARS.fd

swtpm socket --tpmstate dir="./build/debug_env/" --ctrl type=unixio,path="./build/debug_env/swtpm-sock" --tpm2 --daemon

setsid qemu-system-x86_64 \
 -enable-kvm -cpu host -smp cores=4 \
 -m 4G \
 -machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on \
 -drive if=pflash,format=raw,unit=0,readonly=on,file=/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd \
 -drive if=pflash,format=raw,unit=1,file=./build/debug_env/OVMF_VARS.fd \
 -kernel "$efi_path" \
 -chardev socket,id=chrtpm,path="./build/debug_env/swtpm-sock" -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
 -s -serial pipe:./build/debug_env/vmserial \
 -name "IntegraBoot" &

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