tpm2_takeownership -o owner123 -e endorsement123 -l lockout123
tpm2_createprimary -A o -P owner123 -K primary123 -g 0x000B -G 0x0023 -C primary.ctx
tpm2_evictcontrol -A o -c primary.ctx -S 0x81000001 -P owner123
tpm2_create -c primary.ctx -P primary123 -K leaf123 -g 0x000B -G 0x0023 -O leafpri.key -o leafpub.key
tpm2_load -c primary.ctx -P primary123 -u leafpub.key -r leafpri.key -n leafname.key -C leaf.ctx
tpm2_evictcontrol -A o -c leaf.ctx -S 0x81020001 -P owner123
tpm2_listpersistent
