openssl s_server -cert leafselfsign.crt -accept 4433 -keyform engine -engine tpm20e_v2 -key "0x81020001;leaf123"