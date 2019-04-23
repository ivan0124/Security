rm ticket.*
tpm2_verifysignature -k 0x81000005 -g 0x000B -m datain.txt -s signature.bin -t ticket.bin