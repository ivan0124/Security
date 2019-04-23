echo "Verify data signature  ..."
tpm2_verifysignature -k 0x81030001 -g 0x000B -m secret.data -s signature_data -t ticketfile