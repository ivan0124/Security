echo "Remove Persistent key store  ..."
tpm2_evictcontrol -A o -H 0x81030001 -S 0x81030001 -P owner123