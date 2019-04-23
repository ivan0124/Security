echo step1:define nvm area with index 0x1500016, 32 bytes, attr=0x2000a, with owner auth
tpm2_nvdefine -x 0x1500016 -a 0x40000001 -s 32 -t 0x8002000A -P owner123
tpm2_nvlist
