echo step1:define nvm area with index 0x1500016, with owner authorization, 32 bytes, attr=0x2000a,owner password
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t 0x8002000A -P owner123
tpm2_nvlist
echo step2:write data from file nv.data
tpm2_nvwrite -x 0x1500016 -a 0x40000001 -P owner123 -f nv.data
echo step3:read data from file nvm
tpm2_nvread -x 0x1500016 -a 0x40000001 -P owner123 -s 32 -o 0
echo step4:release nvm
tpm2_nvrelease -x 0x1500016 -a 0x40000001 -P owner123
tpm2_nvlist
