echo "Decrytping file"
tpm2_rsadecrypt -k 0x81000005 -P RSAleaf123  -I data_encrypted.txt -o dataout.txt
echo "Done"