
#note: these commmands need to be keyed in manually
#echo "Read Pubkey from TPM"
tpm2_readpublic -H 0x81000005 -o RSA.pubkey
#echo "Convert key to PEM format"
dd if=RSA.pubkey of=modulus.bin bs=1 skip=102 count=256
echo 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' | openssl base64 -a -d > header.bin
echo -en '\x02\x03' > mid-header.bin
echo -ne '\x01\x00\x01' > exponent.bin
cat header.bin modulus.bin mid-header.bin exponent.bin > key.der
openssl pkey -inform der -outform pem -pubin -in key.der -out key.pem
openssl rsa -in key.pem -pubin -noout -text
#echo "Verify Signature Using OpenSSL"
dd if=signature.bin of=signature.raw bs=1 skip=6 count=256
openssl dgst -verify key.pem -keyform pem -sha256 -signature signature.raw datain.txt
