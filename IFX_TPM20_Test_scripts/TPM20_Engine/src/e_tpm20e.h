#ifndef E_TPM20_H_
#define E_TPM20_H_

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * OpenSSL typically return 1 on success (as seen in TrouSerS).
 * EVP probably means "enveloped" (Stackoverflow).
 */
#define EVP_SUCCESS ( 1)
#define EVP_FAIL    (-1)

/*
 * OpenSSL internally only, copied from OpenSSL 1.0.1t and file
 * "./crypto/ecdsa/ecs_locl.h".
 */
struct ecdsa_method {
    const char *name;
    ECDSA_SIG *(*ecdsa_do_sign) (const unsigned char *dgst, int dgst_len,
                                 const BIGNUM *inv, const BIGNUM *rp,
                                 EC_KEY *eckey);
    int (*ecdsa_sign_setup) (EC_KEY *eckey, BN_CTX *ctx, BIGNUM **kinv,
                             BIGNUM **r);
    int (*ecdsa_do_verify) (const unsigned char *dgst, int dgst_len,
                            const ECDSA_SIG *sig, EC_KEY *eckey);
# if 0
    int (*init) (EC_KEY *eckey);
    int (*finish) (EC_KEY *eckey);
# endif
    int flags;
    char *app_data;
};


#ifdef  __cplusplus
}
#endif

#endif
