#!/usr/bin/bash

echo "Generating patches between systemd_original and systemd..."
find systemd_original -type f | while read -r file; do
    subpath="${file#systemd_original/}"
    newfile="systemd/$subpath"
    patchfile="patches/$subpath.patch"
    if ! diff -q "$file" "$newfile" > /dev/null; then
        mkdir -p "$(dirname "$patchfile")"
        diff -u "$file" "$newfile" > "$patchfile"
    fi
done
echo "Done!"
exit 0