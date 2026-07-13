#!/bin/bash
# /etc/initcpio/install/one_time_unlock

build() {
    # Add needed standard utilities
    add_binary grep
    add_binary awk
    add_binary cat
    add_binary chmod
    add_binary install

    # Add kernel modules for TPM
    add_module tpm
    add_module tpm_tis
    add_module tpm_tis_core

    # Add TPM2 binaries
    add_binary tpm2_startauthsession
    add_binary tpm2_policypcr
    add_binary tpm2_nvread
    add_binary tpm2_flushcontext
    add_binary tpm2_nvundefine

    # Add all dynamic TSS2 libraries
    for lib in /usr/lib/libtss2-*.so*; do
        if [ -f "$lib" ]; then
            add_file "$lib"
        fi
    done

    # Add the runtime implementation hook script
    add_runscript
}

help() {
    cat <<HELPEOF
Attempts to automatically decrypt the root LUKS partition using a one-time key bound to TPM2 NVRAM slot 0x01A00000.
HELPEOF
}
