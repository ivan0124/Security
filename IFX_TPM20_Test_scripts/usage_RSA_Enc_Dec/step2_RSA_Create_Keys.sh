echo "Create Keys for RSA operation"
#Create Keys for RSA operation
tpm2_createprimary -A o -P owner123 -K RSAprimary123 -g 0x000B -G 0x0001 -C RSAprimary.ctx
tpm2_evictcontrol -A o -c RSAprimary.ctx -S 0x81000004 -P owner123
tpm2_create -c RSAprimary.ctx -P RSAprimary123 -K RSAleaf123 -g 0x000B -G 0x0001 -O RSAPriv.key -o RSAPub.key 
tpm2_load -c RSAprimary.ctx -P RSAprimary123 -u RSAPub.key -r RSAPriv.key -n key_name_structure.data -C RSAkeycontext.ctx
tpm2_evictcontrol -A o -c RSAkeycontext.ctx -S 0x81000005 -P owner123
echo "Done"