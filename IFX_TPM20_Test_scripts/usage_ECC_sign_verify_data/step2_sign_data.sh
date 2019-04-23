echo "sign data with ECC key, with SHA256 algo"
tpm2_sign -k 0x81020001 -P leaf123 -g 0x000B -m secret.data -s signature_data

