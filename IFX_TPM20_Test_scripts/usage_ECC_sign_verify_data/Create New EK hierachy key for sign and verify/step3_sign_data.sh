echo "Sign data  ..."
tpm2_sign -k 0x81030001 -P en_leaf123 -g 0x000B -m secret.data -s signature_data