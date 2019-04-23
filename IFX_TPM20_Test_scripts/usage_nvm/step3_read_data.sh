echo step3:read data from file nvm
tpm2_nvread -x 0x1500016 -a 0x40000001 -P owner123 -s 32 -o 0