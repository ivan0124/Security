echo "Encrytping file"
tpm2_rsaencrypt -k 0x81000005 -I datain.txt -o data_encrypted.txt
echo "Done"