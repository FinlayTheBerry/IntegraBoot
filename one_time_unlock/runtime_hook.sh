#!/usr/bin/ash
# /etc/initcpio/hooks/one_time_unlock

run_hook() {
    local quiet rootdelay

    echo "Loading modules"

    # Load needed kernel modules
    modprobe -a -q dm-crypt >/dev/null 2>&1
    modprobe -a -q tpm tpm_tis tpm_tis_core >/dev/null 2>&1

    echo "Parsing cryptdevice"

    # Parse cryptdevice and return if arg missing
    if [ -n "${cryptdevice}" ]; then
        IFS=: read cryptdev cryptname cryptoptions <<EOF
$cryptdevice
EOF
    else
        return 0
    fi

    echo "Got ${cryptdev} ${cryptname} ${cryptoptions}"

    # Bail if cryptname already mapped
    if [ -b "/dev/mapper/${cryptname}" ]; then
        return 0
    fi

    echo "Parsing crypt options."

    # Parse any known crypt options
    set -f
    OLDIFS="$IFS"; IFS=,
    for cryptopt in ${cryptoptions}; do
        case ${cryptopt} in
            allow-discards|discard)
                cryptargs="${cryptargs} --allow-discards"
                ;;
            no-read-workqueue|perf-no_read_workqueue)
                cryptargs="${cryptargs} --perf-no_read_workqueue"
                ;;
            no-write-workqueue|perf-no_write_workqueue)
                cryptargs="${cryptargs} --perf-no_write_workqueue"
                ;;
            sector-size=*)
                cryptargs="${cryptargs} --sector-size ${cryptopt#*=}"
                ;;
            *)
                echo "Encryption option '${cryptopt}' not known, ignoring." >&2
                ;;
        esac
    done
    echo "Got ${cryptopt}"

    set +f
    IFS="$OLDIFS"
    unset OLDIFS

    # Attempt to resolve crypt device
    rootdelay="$(getarg rootdelay)"
    echo "Resolving root device after ${rootdelay} delay"
    if ! resolved=$(resolve_device "${cryptdev}" "${rootdelay}"); then
        echo "Failed to resolve device ${cryptdev}" >&2
        return 0
    fi
    echo "Got ${resolved}"

    if ! cryptsetup isLuks "${resolved}" >/dev/null 2>&1; then
        echo "Device ${resolved} is not encrypted" >&2
        return 0
    fi

    # Clear and create temp dir
    echo "Creating temp dir"
    rm -rf /tmp/one_time_unlock/
    install -o +0 -g +0 -m 700 -d /tmp/one_time_unlock/

    # Start a TPM auth session
    echo "Starting TPM auth session"
    tpm2_startauthsession -S /tmp/one_time_unlock/session.ctx --policy-session
    chmod 600 /tmp/one_time_unlock/session.ctx

    # Add the current value of PCR4 to our session
    echo "Adding current value of PCR4 to TPM auth session"
    tpm2_policypcr -S /tmp/one_time_unlock/session.ctx --pcr-list="sha256:4"

    # Attempt to read the key from TPM NVRAM using our session
    echo "Reading key from TPM NVRAM"
    (umask 0077; tpm2_nvread 0x01A00000 -P "session:/tmp/one_time_unlock/session.ctx" >/tmp/one_time_unlock/key.bin)

    # Exit the current session
    echo "Exiting current auth session"
    tpm2_flushcontext /tmp/one_time_unlock/session.ctx

    # Delete the key from TPM NVRAM
    echo "Deleting key from TPM"
    tpm2_nvundefine 0x01A00000

    # If the key size is zero then bail since the TPM gave us nothing
    if [ ! -s /tmp/one_time_unlock/key.bin ]; then
        echo "Failed to read key from TPM." >&2
        rm -rf /tmp/one_time_unlock/
        return 0
    fi

    # Attempt to open the luks drive using the key from the TPM
    if ! cryptsetup open --batch-mode --key-file /tmp/one_time_unlock/key.bin --verbose "${resolved}" "${cryptname}" "${cryptargs}" >/tmp/one_time_unlock/cryptsetup.log 2>&1; then
        echo "Failed to unlock luks device with key from TPM." >&2
        rm -rf /tmp/one_time_unlock/
        return 0
    fi

    # Remove the keyslot from the luks drive
    key_slot=$(cat /tmp/one_time_unlock/cryptsetup.log | grep "Key slot" | awk '{print $3}')
    cryptsetup luksKillSlot --batch-mode "${resolved}" "${key_slot}" >/dev/null 2>&1

    # Remove the temp dir and the key inside. No need to shred since /tmp is memory backed.
    rm -rf /tmp/one_time_unlock/
}
