echo -n "Enter passphrase for /dev/nvme2n1p2: "
read passphrase
if echo "$passphrase" | cryptsetup open --test-passphrase /dev/nvme2n1p2; then
	echo "$passphrase" | cryptsetup luksDump --dump-master-key /dev/nvme2n1p2 | grep -A 3 "MK dump:" | grep -oE '[0-9a-fA-F]{2}' | tr -d '\n' | xxd -r -p > masterkey
	
fi


install -o +0 -g +0 -m 700 -d /tmp/integraboot-pcr
dd if=/dev/random of=/tmp/integraboot-pcr/key bs=1 count=32
cryptsetup luksAddKey /dev/nvme2n1p2 /tmp/integraboot-pcr/key
tpm2_createpolicy --policy-pcr --pcr-list="sha256:4" --pcr-values="sha256:4=${FUTURE_PCR4}" --policy=/tmp/integraboot-pcr/policy
tpm2_nvdefine 0x01A00000 -C o -s 32 --policy=/tmp/integraboot-pcr/policy -a "ownerread|policyread|ownerwrite"
tpm2_nvwrite 0x01A00000 -C o -i /tmp/integraboot-pcr/key
rm -rf /tmp/integraboot-pcr

cryptsetup luksRemoveKey /dev/nvme2n1p2 --key-file=/home/finlaytheberry/tpmunlock/key.bin




Enroll:
0x01A00000

Read
tpm2_startauthsession -S ./session.ctx --policy-session
tpm2_policypcr -S ./session.ctx --pcr-list="sha256:4,7"
tpm2_nvread 0x1500000 -P "session:./session.ctx"
tpm2_flushcontext ./session.ctx

Unenroll
