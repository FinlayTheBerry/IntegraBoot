#!/usr/bin/bash
cd "$(dirname "$0")"

# Confirm with the user that they want to destroy the contents of systemd
read -p "The contents of ./systemd will be reset to systemd upstream. Are you sure? (y/N): " response
if [[ ! "$response" =~ ^([yY]|[yY][eE][sS])$ ]]; then
    echo "Aborting! Nothing changed."
    exit 1
fi

# Remove old source if it exists
rm -rf systemd

# Download the latest source tarball from GitHub
tarball_url="$(curl -s https://api.github.com/repos/systemd/systemd/releases/latest | jq -r ".tarball_url")"
echo "Downloading latest SystemD release from $tarball_url..."
curl -L "$tarball_url" -o systemd.tar.gz  --progress-bar

# Extract the source
echo "Extracting SystemD..."
tar -xf systemd.tar.gz
mv systemd-systemd-* systemd

# Remove the tarball since we don't need it anymore
rm systemd.tar.gz

# Build the list of files to keep from the systemd source
echo "Removing unused SystemD source files..."
mapfile -t keeplist <<EOF
LICENSE.GPL2
LICENSE.LGPL2.1
CITATION.cff
LICENSES/murmurhash2-public-domain.txt
LICENSES/alg-sha1-public-domain.txt
LICENSES/LGPL-2.0-or-later.txt
LICENSES/README.md
LICENSES/MIT.txt
LICENSES/CC0-1.0.txt
LICENSES/MIT-0.txt
LICENSES/BSD-2-Clause.txt
LICENSES/Linux-syscall-note.txt
LICENSES/lookup3-public-domain.txt
LICENSES/OFL-1.1.txt
LICENSES/BSD-3-Clause.txt
tools/elf2efi.py
src/boot/part-discovery.h
src/boot/random-seed.h
src/fundamental/unaligned-fundamental.h
src/boot/util.c
src/boot/efi-log.h
src/boot/efi-firmware.h
src/boot/proto/simple-text-io.h
src/boot/proto/dt-fixup.h
src/boot/efi-string.h
src/fundamental/sha1-fundamental.c
src/boot/proto/cc-measurement.h
src/fundamental/logarithm.h
src/boot/export-vars.c
src/boot/sysfail.h
src/boot/shim.h
src/boot/stub.c
src/boot/pe.h
src/boot/drivers.c
src/boot/devicetree.h
src/fundamental/efivars-fundamental.c
src/boot/drivers.h
src/boot/proto/edid-discovered.h
src/boot/proto/console-control.h
src/boot/graphics.h
src/fundamental/assert-fundamental.h
src/fundamental/efivars-fundamental.h
src/boot/linux_x86.c
src/boot/measure.c
src/boot/cpio.c
src/fundamental/iovec-util-fundamental.h
src/boot/smbios.c
src/boot/secure-boot.c
src/boot/chid.c
src/fundamental/sha256-fundamental.c
src/fundamental/bootspec-fundamental.h
src/boot/efi-efivars.c
src/fundamental/confidential-virt-fundamental.h
src/boot/url-discovery.c
src/boot/proto/rng.h
src/boot/proto/load-file.h
src/boot/vmm.c
src/boot/smbios.h
src/boot/proto/device-path.h
src/boot/efi-firmware.c
src/boot/device-path-util.c
src/boot/edid.h
src/fundamental/cleanup-fundamental.h
src/fundamental/macro-fundamental.h
src/boot/proto/shell-parameters.h
src/boot/initrd.h
src/boot/graphics.c
src/boot/proto/file-io.h
src/boot/device-path-util.h
src/boot/proto/memory-attribute.h
src/boot/efi-string-table.h
src/boot/url-discovery.h
src/boot/part-discovery.c
src/boot/cpio.h
src/fundamental/sbat.h
src/boot/export-vars.h
src/boot/efi-efivars.h
src/fundamental/bootspec-fundamental.c
src/boot/splash.h
src/boot/sysfail.c
src/boot/linux.h
src/fundamental/efi-fundamental.h
src/fundamental/uki.c
src/boot/initrd.c
src/boot/proto/loaded-image.h
src/boot/ticks.c
src/fundamental/uki.h
src/fundamental/memory-util-fundamental.h
src/boot/ticks.h
src/fundamental/edid-fundamental.h
src/boot/chid.h
src/boot/proto/tcg.h
src/boot/splash.c
src/fundamental/string-util-fundamental.c
src/boot/proto/block-io.h
src/boot/measure.h
src/fundamental/edid-fundamental.c
src/fundamental/sha1-fundamental.h
src/boot/console.h
src/boot/console.c
src/fundamental/sha256-fundamental.h
src/fundamental/tpm2-pcr.h
src/boot/efi.h
src/boot/proto/graphics-output.h
src/boot/linux.c
src/fundamental/string-util-fundamental.h
src/boot/shim.c
src/fundamental/chid-fundamental.h
src/boot/pe.c
src/fundamental/chid-fundamental.c
src/boot/secure-boot.h
src/boot/efi-log.c
src/boot/random-seed.c
src/boot/edid.c
src/boot/efi-string.c
src/boot/vmm.h
src/boot/util.h
src/boot/proto/security-arch.h
src/boot/devicetree.c
EOF

# Build array of args to find command from the keep list
findargs=()
for keeppath in "${keeplist[@]}"; do
    findargs+=("!" "-wholename" "systemd/$keeppath")
    done

# Remove all files and folders not in the keep list
find systemd/ -type l -delete
find systemd/ -type f "${findargs[@]}" -delete
find systemd/ -depth -type d -delete 2>/dev/null

echo "Done!"
exit 0