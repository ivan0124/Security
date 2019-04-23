#include <string.h>
#include <signal.h>

#include <openssl/engine.h>
#include <openssl/ossl_typ.h>

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

#include "common.h" // from TPM 2.0 Tools

#include "e_tpm20e.h"
#include "tpm20w.h"

/**********************************************************************
 * COMMON / GENERAL / DEBUG                                           *
 **********************************************************************/
 
static const char *engine_tpm20e_id   = "tpm20e_v2";
static const char *engine_tpm20e_name = "TPM 2.0 engine by Infineon Technologies AG / Christian Lesjak / Version 2";

int myprintf(printf_type type, const char *format, ...);

int myprintf(printf_type type, const char *format, ...)
{
  return printf(format, type);
}

int (*printfFunction)( printf_type type, const char *format, ...) = myprintf;

void fprintBuffer(
  FILE*                file,
  const unsigned char* buffer,
  const int            size);

void fprintBuffer(
  FILE*                file,
  const unsigned char* buffer,
  const int            size)
{
  int i;
  
  for (i = 0; i < size; i++)
  {
    fprintf(file, "%2x", buffer[i]);
  }
}



/**********************************************************************
 * ENGINE INSTANCE GLOBAL DATA STORAGE                                *
 **********************************************************************/

void tpm20e_tssStart(void);
void tpm20e_tssStop(void);
void intHandler(int dummy);

#define KEY_CONTEXT_MAX_LEN (1024)
static char keyContext[KEY_CONTEXT_MAX_LEN] = { 0 };

#define OBJ_MAX_LEN (128) /* Maximum length for key object paths or passwords */

#define TSS_STATUS_NULL (0) /* unknown state, before startup */
#define TSS_STATUS_INIT (1) /* TSS initialized and in use    */
#define TSS_STATUS_DEST (2) /* TSS destroyed                 */
static int tssStatus = { TSS_STATUS_NULL };



void intHandler(
  int  sig)
{
  DBGFN("Interrupt handler for CTRL-C entered.");
  signal(sig, intHandler);
  DBGFN("Calling to stop RM...");
  tpm20e_tssStop();
  DBGFN("Interrupt handler for CTRL-C done.");
}



void tpm20e_tssStart(void)
{
  DBGFN("Initializing resource manager and system context.");
  
  if (tssStatus == TSS_STATUS_DEST || tssStatus == TSS_STATUS_NULL)
  {
    prepareTest(
      DEFAULT_HOSTNAME, // Resource manager host name
      DEFAULT_RESMGR_TPM_PORT, // Resource manager port
      0); // Debug level
    tssStatus = TSS_STATUS_INIT;
  }

  signal(SIGINT, intHandler);
}



void tpm20e_tssStop(void)
{
  DBGFN("Tearing down resource manager and system context.");
  if (tssStatus == TSS_STATUS_INIT)
  {
    finishTest();
    tssStatus = TSS_STATUS_DEST;
  }
  else
  {
    DBGFN("Nothing to do, contexts were not initialized (any more).");
  }
}



/**********************************************************************
 * RANDOM                                                             *
 **********************************************************************/

int tpm20e_getRandomBytes(
  unsigned char *buffer,
  int nrBytes);

int tpm20e_getRandomStatus(void);

static RAND_METHOD tpm20e_random_method =
{
  NULL,                        // seed
  tpm20e_getRandomBytes,       // get random bytes
  NULL,                        // cleanup
  NULL,                        // add
  tpm20e_getRandomBytes,       // pseudorandom
  tpm20e_getRandomStatus       // status
};



int tpm20e_getRandomStatus(void)
{
  DBGFN("Get random status...");
  return EVP_SUCCESS;
}



int tpm20e_getRandomBytes(
  unsigned char *buffer,
  int           nrBytes)
{
  TPM_RC        rval;
  TPM2B_DIGEST  randomBytes = { { sizeof(TPM2B_DIGEST), } };
  int           nrBytesLeft;
  int           maxBytesPerCall = 0x20;
  int           nrBytesNextReq;
  int           result = -1; // Error
  char          *returnBytes = (char*) buffer;

  DBGFN("Get %d random bytes...", nrBytes);

  memset(returnBytes, 0xFF, nrBytes);

  nrBytesLeft = nrBytes;
  
  tpm20e_tssStart(); 
 
  while (nrBytesLeft > 0)
  {
    nrBytesNextReq = (nrBytesLeft > maxBytesPerCall) ? maxBytesPerCall : nrBytesLeft;

    DBGFN("Tss2_Sys_GetRandom with %d Bytes.", nrBytesNextReq);
    rval = Tss2_Sys_GetRandom(
      sysContext,
      NULL,
      nrBytesNextReq,
      &randomBytes,
      NULL);

    if (rval == TSS2_RC_SUCCESS)
    {
      result = EVP_SUCCESS;
    }
    else
    {
      ERRFN("TPM error 0x%x.", rval);
      result = -1;
      break;
    }

    memcpy(returnBytes, randomBytes.t.buffer, randomBytes.t.size);
    returnBytes += randomBytes.t.size;

    nrBytesLeft -= randomBytes.t.size;
  }

  tpm20e_tssStop();
  return result;
}



/**********************************************************************
 * ECDSA                                                              *
 **********************************************************************/

int tpm20e_ecdsa_signSetup(
  EC_KEY   *eckey,
  BN_CTX   *ctx_in,
  BIGNUM  **kinvp,
  BIGNUM  **rp
);

static ECDSA_SIG* tpm20e_ecdsa_sign(
  const unsigned char  *dgst,
  int                   dgst_len,
  const BIGNUM         *inv,
  const BIGNUM         *rp,
  EC_KEY               *eckey
);

int tpm20e_ecdsa_doVerify(
  const unsigned char  *digest,
  int                   digest_len,
  const ECDSA_SIG      *ecdsa_sig,
  EC_KEY               *eckey
);
  
static int parseKeyParams(
  char  *in, // implicitly expects a NULL terminated string!
  int    n,
  char  *args[]
);



static ECDSA_METHOD tpm20e_ecdsa_method = {
  "TPM 2.0 engine ECDSA method",
  tpm20e_ecdsa_sign,          // sign
  tpm20e_ecdsa_signSetup,     // sign setup
  tpm20e_ecdsa_doVerify,      // do verify
# if 0
  NULL,                       // init
  NULL,                       // finish
# endif
  0,                          // flags
  NULL                        // app_data
};



int tpm20e_ecdsa_signSetup(
  EC_KEY   *eckey,
  BN_CTX   *ctx_in,
  BIGNUM  **kinvp,
  BIGNUM  **rp)
{
  DBGFN("ECDSA signature setup");
  // TODO (not implemented): Currently I don't need this hook, maybe in the future
  return EVP_SUCCESS;
}



/**********************************************************************
 * Returns -1 (error) or the number of arguments parsed.
 **********************************************************************/
static int parseKeyParams(
  char       *in,      // Implicitly expecting NULL terminated string!
  int        n,
  char       *args[])
{
  char* token;
  int   i;
  char  in2[KEY_CONTEXT_MAX_LEN];
  
  strncpy(in2, in, KEY_CONTEXT_MAX_LEN);
  
  if (in == NULL)
  {
    ERRFN("No input key parameters present.");
    return EVP_FAIL;
  }
  
  if (n == 0)
  {
    ERRFN("n is 0");
    return -1;
  }
  
  if (args == NULL)
  {
    ERRFN("Argument store is NULL.");
    return EVP_FAIL;
  }
  
  for (i = 0; i < n; i++)
  {
    if (args[i] == NULL)
    {
      ERRFN("Argument store %d is NULL.", i);
      return EVP_FAIL;
    }
  }
  
  token = strtok(in2, ";");
  for (i = 0; i < n; i++)
  {
    if (token == NULL)
    {
      ERRFN("Too few parameters in key parameters list (less than %d).", i);
      return EVP_FAIL;
    }
      
    strncpy(args[i], token, OBJ_MAX_LEN);    
    token = strtok(NULL, ";");
  }

  return n;
}



static ECDSA_SIG* tpm20e_ecdsa_sign(
  const unsigned char  *dgst,
  int                   dgst_len,
  const BIGNUM         *inv,
  const BIGNUM         *rp,
  EC_KEY               *eckey
)
{
  // TODO (Enhancement): get the key password(s) from the dedicated 'pass' arguments for OpenSSL  
  
  DBGFN("ECDSA signature calculation with &EC_KEY=0x%x und key_id=%s.", 
    (unsigned int) eckey,
    keyContext);
    
  ECDSA_SIG       *sigFormatOssl;
  TPMT_SIGNATURE   sigFormatTpm2;
  TPMI_DH_OBJECT   keyHandle;
  int              status;
  
  char keyHandleHexStr[128] = { 0 };
  char keyPasswordStr [128] = { 0 };
  
  char* args[] = {
    keyHandleHexStr,
    keyPasswordStr,
  };
  
  while (1)
  {
    if ((status = parseKeyParams(keyContext, 2, args)) != 2)
    {
      ERRFN("Invalid key parameter (returned %d).", status);
      break;
    }
    
    if ((status = getSizeUint32Hex(keyHandleHexStr, &keyHandle)) != 0)
    {
      ERRFN("Invalid key handle (returned %d).", status);
      break;
    }
    DBGFN("Key handle = '0x%8x'", keyHandle);

    DBG(" Key param 'key handle' = '%s'",   keyHandleHexStr);
    DBG(" Key param 'key password' = '%s'", keyPasswordStr);
    
    // Hack if digest is too long
    if (dgst_len > 32)
    {
      // TODO: this is a hack - OpenSSL 1.0.1 does present all possible signature algs
      // But the OPTIGA TPM SLB9670 only supports 32 Byte SHA-256 digests
      // This trunction works, as only the left-most 32 Byte are used with EC keys
      // on the PRIME256 curve
      // The following clean solution (for the engine user) is not supported in OpenSSL 1.1
      //  SSL_CTX_set1_sigalgs_list(ctx, "ECDSA+SHA256");
      dgst_len = 32;
      ERRFN("Applying hack for digest size > 32 Byte");
    }
   
    tpm20e_tssStart();
 
    if ((status = tpm20w_signEcdsaWithSha256(
       dgst,
       dgst_len,
       keyHandle,
       keyPasswordStr,
      &sigFormatTpm2
    )) != 1)
    {
      ERRFN("Signature computation failed, returned 0x%x.", status);
      break;
    }

    if ((sigFormatOssl = ECDSA_SIG_new()) == NULL)
    {
      ERRFN("signature = ECDSA_SIG_new() failed.");
      break;
    }
    
    BN_bin2bn(
      sigFormatTpm2.signature.ecdsa.signatureR.t.buffer, 
      sigFormatTpm2.signature.ecdsa.signatureR.t.size, 
      sigFormatOssl->r);
    BN_bin2bn(
      sigFormatTpm2.signature.ecdsa.signatureS.t.buffer, 
      sigFormatTpm2.signature.ecdsa.signatureS.t.size, 
      sigFormatOssl->s);

    DBGFN("Signing successfully done.");
    tpm20e_tssStop();
    return sigFormatOssl;
  }

  tpm20e_tssStop();
  return (ECDSA_SIG*) NULL; // ERROR
}



int tpm20e_ecdsa_doVerify(
  const unsigned char *digest,
  int digest_len,
  const ECDSA_SIG *ecdsa_sig,
  EC_KEY *eckey)
{
  DBGFN("ECDSA signature verification (engine hook)");
  
  // This is done natively by OpenSSL, not by our TPM
  // TODO: use this hook in the future, if necessary
  
  return -1;
}

/**********************************************************************
 * LOAD KEYS                                                          *
 **********************************************************************/

static EVP_PKEY *tpm20e_loadPrivateKey(
  ENGINE *e,
  const char *key_id,
  UI_METHOD *ui,
  void *cb_data);

static EVP_PKEY *tpm20e_loadPublicKey(
  ENGINE *e,
  const char *key_id,
  UI_METHOD *ui,
  void *cb_data);

/*
 * For reference of data types, look into:
 * > 'struct ec_key_st' in 'OpenSSL/crypto/ec/ec_lcl.h'
 * 
 * Findings:
 *   $ openssl pkey -in mykeyid -engine tpm20e -inform ENGINE -text_pub -noout
 *   Here, the mykeyid lands in *key_id variable as string
 */
static EVP_PKEY *tpm20e_loadPrivateKey(
  ENGINE*      e,
  const char*  key_id,
  UI_METHOD*   ui,
  void*        cb_data)
{
  TPMI_DH_OBJECT   keyHandle;
  EVP_PKEY*        key;
  EC_KEY          *ecKey = NULL;
  int              status;
  
  strncpy(keyContext, key_id, KEY_CONTEXT_MAX_LEN);
  
  char keyHandleHexStr[128] = { 0 };
  char keyPasswordStr [128] = { 0 };
  
  char* args[] = {
    keyHandleHexStr,
    keyPasswordStr,
  };
  
  while (1)
  {
    if ((status = parseKeyParams(keyContext, 2, args)) != 2)
    {
      ERRFN("Invalid key parameter (returned %d).", status);
      break;
    }
    
    if ((status = getSizeUint32Hex(keyHandleHexStr, &keyHandle)) != 0)
    {
      ERRFN("Invalid key handle (returned %d).", status);
      break;
    }
    DBGFN("Key handle = '0x%8x'", keyHandle);
   
    tpm20e_tssStart(); 
    if ((status = tpm20w_readPublic(keyHandle, &ecKey)) != 0)
    {
      ERRFN("Could not read public key from TPM (returned %d).", status);
      break;
    }
    
    key = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(key, ecKey);
    
    DBGFN("Return with &EVP_PKEY=0x%x and &EC_KEY=0x%x",
      (unsigned int) key,
      (unsigned int) ecKey);

    tpm20e_tssStop();
    return key; // RETURN SUCCESS
  }
  
  tpm20e_tssStop(); 
  return (EVP_PKEY*) NULL; // RETURN FAIL
}

static EVP_PKEY *tpm20e_loadPublicKey(  
  ENGINE*      e,
  const char*  key_id,
  UI_METHOD*   ui,
  void*        cb_data)
{
  DBGFN("Load public key");
  
  // TODO (not implemented)
  
  return (EVP_PKEY*) NULL;
}

/**********************************************************************
 * ENGINE LIFECYCLE AND MANAGEMENT                                    *
 **********************************************************************/

int tpm20e_engine_init(
  ENGINE *e);
int tpm20e_engine_finish(
  ENGINE *e);
int tpm20e_engine_destroy(
  ENGINE *e);
int bind_helper(
  ENGINE * e,
  const char *id);

int tpm20e_engine_init(ENGINE *e) {
  DBGFN("Engine init.");
  
  tpm20e_tssStart();
  
  return EVP_SUCCESS;
}

int tpm20e_engine_finish(ENGINE *e) {
  DBGFN("Engine finish.");
  
  tpm20e_tssStop();
  
  return EVP_SUCCESS;
}

int tpm20e_engine_destroy(ENGINE *e) {
  DBGFN("Engine destroy.");
  
  tpm20e_tssStop();
  
  return EVP_SUCCESS;
}

int bind_helper(ENGINE * e, const char *id)
{
  DBGFN("Engine bind helper");
  
  const ECDSA_METHOD* ecdsaMethod = ECDSA_get_default_method();
  if (ecdsaMethod == NULL || 
      ecdsaMethod->ecdsa_do_verify == NULL)
  {
    ERRFN("No default ECDSA verfication method available.");
    return 0;
  }
  // Workaround to keept the verification in OpenSSL, not on TPM
  tpm20e_ecdsa_method.ecdsa_do_verify = ecdsaMethod->ecdsa_do_verify;
  
  if (!ENGINE_set_id                   (e,  engine_tpm20e_id)       ||
      !ENGINE_set_name                 (e,  engine_tpm20e_name)     ||
      !ENGINE_set_init_function        (e,  tpm20e_engine_init)     ||
      !ENGINE_set_destroy_function     (e,  tpm20e_engine_destroy)  ||
      !ENGINE_set_finish_function      (e,  tpm20e_engine_finish)   ||
      !ENGINE_set_RAND                 (e, &tpm20e_random_method)   ||
  //    !ENGINE_set_load_pubkey_function (e,  tpm20e_loadPublicKey)   || // TODO: currently not used
      !ENGINE_set_load_privkey_function(e,  tpm20e_loadPrivateKey)  ||
      !ENGINE_set_ECDSA                (e, &tpm20e_ecdsa_method))
  {
    ERRFN("Error binding engine functions.");
    return 0;
  }
  return EVP_SUCCESS;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_helper)
