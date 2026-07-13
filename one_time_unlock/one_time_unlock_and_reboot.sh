#!/bin/sh

# Restart with sudo if not running as root
if [ "$(id -u)" != "0" ]; then
    exec sudo "$0" "$@"
fi

# Check if the system has a TPM
if [ ! -e /sys/class/tpm/tpm0 ]; then
    echo "This feature requires a motherboard with a tpm2 chip."
    exit 1
fi

# Check if the system TPM is version 2
if [ "$(cat /sys/class/tpm/tpm0/tpm_version_major)" != "2" ]; then
    echo "This feature requires a motherboard with a tpm2 chip."
    exit 1
fi

# Get crypt root dev aka /dev/mapper/crypt_root
root_crypt_dev=$(findmnt --noheadings --output SOURCE /)

# Clear and create temp dir
rm -rf /tmp/one_time_unlock/
install -o +0 -g +0 -m 700 -d /tmp/one_time_unlock/

# Get root dev aka /dev/sda1
if ! cryptsetup status "${root_crypt_dev}" >/tmp/one_time_unlock/cryptsetup.log; then
    echo "The root device doesn't appear to be encrypted."
    rm -rf /tmp/one_time_unlock/
    exit 1
fi
root_dev=$(cat /tmp/one_time_unlock/cryptsetup.log | grep "device:" | awk '{print $2}')

# Generate temp key
(umask 0077; dd if=/dev/random of=/tmp/one_time_unlock/luks_key.bin bs=1 count=32 1>/dev/null 2>&1)

# Prompt user to enter their passphrase to approve adding the new LUKS key
cryptsetup luksAddKey --batch-mode "${root_dev}" /tmp/one_time_unlock/luks_key.bin

# Compute the predicted value for PCR 4 based upon current bootloader
/important_data/Coding/EpsilonOS/integraboot/one_time_unlock/predict.py | xxd -r -p > /tmp/one_time_unlock/future_pcrs

# Create a TPM policy bound to that future value of PCR 4
tpm2_createpolicy --policy-pcr --pcr-list="sha256:4" --pcr=/tmp/one_time_unlock/future_pcrs --policy=/tmp/one_time_unlock/pcr.policy 1>/dev/null 2>&1

# Define a new variable in TPM NVRAM bound by the policy we just created
tpm2_nvdefine 0x01A00000 -C o -s 32 --policy=/tmp/one_time_unlock/pcr.policy -a "ownerread|policyread|ownerwrite" 1>/dev/null 2>&1

# Write the new luks key into that variable
tpm2_nvwrite 0x01A00000 -C o -i /tmp/one_time_unlock/luks_key.bin

# Remove the temp dir and the key inside. No need to shred since /tmp is memory backed.
rm -rf /tmp/one_time_unlock/

# Finally restart the system
systemctl reboot
