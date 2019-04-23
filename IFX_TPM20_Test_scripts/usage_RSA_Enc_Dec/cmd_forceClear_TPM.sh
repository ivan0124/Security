tpm2_takeownership -c -L lockout123
rm *.ctx
rm *.key
tpm2_dump_capability -c properties-variable