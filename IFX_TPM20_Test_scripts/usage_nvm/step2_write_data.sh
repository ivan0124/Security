echo step2:write data from file nv.data
tpm2_nvwrite -x 0x1500016 -a 0x40000001 -P owner123 -f nv.data