echo "Load Pubkey received into TPM and verify signature and data ..."
rm ticketfile*
tpm2_loadexternal -H o -u ../tpm_setup/leafpub.key -C verifyleaf.ctx
tpm2_verifysignature -c verifyleaf.ctx -g 0x000B -m secret.data -s signature_data -t ticketfile