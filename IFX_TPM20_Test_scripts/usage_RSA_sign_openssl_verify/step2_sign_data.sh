echo "sign data with RSA key, with SHA256 algo"
tpm2_hash -H e -g 0x00B -I datain.txt -o hash.bin -t ticket.bin
tpm2_sign -k 0x81000005 -P RSAleaf123 -g 0x000B -m datain.txt -s signature.bin -t ticket.bin 
echo "Done"

