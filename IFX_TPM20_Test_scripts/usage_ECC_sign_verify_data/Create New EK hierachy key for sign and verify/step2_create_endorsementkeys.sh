echo "Create keys ..."
tpm2_createprimary -A e -P endorsement123 -K enp123 -g 0x000B -G 0x0023 -C en_primary.ctx
tpm2_create -c en_primary.ctx -P enp123 -K en_leaf123 -g 0x000B -G 0x0023 -O enleafpri.key -o enleafpub.key
tpm2_load -c en_primary.ctx -P enp123 -u enleafpub.key -r enleafpri.key -n leafname.key -C enleaf.ctx
tpm2_evictcontrol -A o -c enleaf.ctx -S 0x81030001 -P owner123