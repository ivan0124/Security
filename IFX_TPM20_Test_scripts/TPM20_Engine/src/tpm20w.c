#include "tpm20w.h"

#include <openssl/obj_mac.h>


int load(
  TPMI_DH_OBJECT   parentHandle,
  TPM2B_PUBLIC    *inPublic,
  TPM2B_PRIVATE   *inPrivate,
  const char      *outFileName,
  TPM_HANDLE      *keyHandle);


TPMS_AUTH_COMMAND   sessionData;


int tpm20w_signEcdsaWithSha256(
  const unsigned char  *digestBytes,
  int                   digestLen,
  TPMI_DH_OBJECT        keyHandle,
  const char           *keyPassword,
  TPMT_SIGNATURE       *signature)
{
  TPMI_ALG_HASH        halg = 0x000B; // SHA-256

  TPM2B_DIGEST         digest = { {sizeof(TPM2B_DIGEST), } };
  TPMT_SIG_SCHEME      inScheme;
  
  TPMT_TK_HASHCHECK    validation;

  TSS2_SYS_CMD_AUTHS   sessionsData;
  TPMS_AUTH_RESPONSE   sessionDataOut;
  TSS2_SYS_RSP_AUTHS   sessionsDataOut;
  TPMS_AUTH_COMMAND*   sessionDataArray[1];
  TPMS_AUTH_RESPONSE*  sessionDataOutArray[1];
    
  UINT32 status;

  sessionDataArray[0] = &sessionData;
  sessionsData.cmdAuths = &sessionDataArray[0];
  sessionDataOutArray[0] = &sessionDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;
  sessionsData.cmdAuthsCount = 1;
  
  sessionData.sessionHandle = TPM_RS_PW;
  sessionData.nonce.t.size = 0;
  *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;
  
  validation.tag = TPM_ST_HASHCHECK;
  validation.hierarchy = TPM_RH_NULL;
  validation.digest.t.size = 0;
  
  do
  {
    DBGFN("Key password: '%s'", keyPassword);
     
    // Prepare password for key
    sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
    if ((status = str2ByteStructure(
      keyPassword,
      &sessionData.hmac.t.size,
      sessionData.hmac.t.buffer)) != 0)
    {
      ERRFN("Error setting key password, returned 0x%x.", status);
      break;
    }

    inScheme.scheme = TPM_ALG_ECDSA;
    inScheme.details.ecdsa.hashAlg = halg;
    digest.t.size = digestLen;
    memcpy(digest.t.buffer, digestBytes, digestLen);
    
    DBGFN("System context at 0x%x", (unsigned int) sysContext);
    DBGFN("Key handle: 0x%x", keyHandle);
    DBGFN("Session Data at 0x%x", (unsigned int) &sessionData);
    DBGFN("Digest size: %d", digestLen);
    DBGFN("In-scheme at 0x%x", (unsigned int) &inScheme);

    if ((status = Tss2_Sys_Sign(
       sysContext,
       keyHandle,
      &sessionsData,
      &digest,
      &inScheme,
      &validation,
       signature,
      &sessionsDataOut)) != TPM_RC_SUCCESS)
    {
      ERRFN("Tss2_Sys_Sign failed with error code 0x%x.", status);
      break;
    }
    
    return 1; // SUCCESS
  } while (0);
  
  return -1;
}

int tpm20w_loadSigningKey(
  const char* parentFilePath,
  const char* parentPassword,
  const char* objectFilePath,
  TPM_HANDLE* keyHandle)
{
  char nameStructureFilePath[128];
  char publicComponentFilePath[128];
  char privateComponentFilePath[128];
  char contextParentFilePath[128];
  
  TPMI_DH_OBJECT parentHandle;
  TPM2B_PUBLIC   inPublic;
  TPM2B_PRIVATE  inPrivate;
  
  int status;
  int size;
  
  memset(&inPublic,  0, sizeof(TPM2B_PUBLIC));
  memset(&inPrivate, 0, sizeof(TPM2B_SENSITIVE));
  
  strncpy(contextParentFilePath, parentFilePath, 128);
  strcat(contextParentFilePath, "/context");
  
  strncpy(nameStructureFilePath, objectFilePath, 128);
  strcat(nameStructureFilePath, "/name");
    
  strncpy(publicComponentFilePath, objectFilePath, 128);
  strcat(publicComponentFilePath, "/public"); 
   
  strncpy(privateComponentFilePath, objectFilePath, 128);
  strcat(privateComponentFilePath, "/private");
  
  DBGFN("Loading signing key with");
  DBG("  contextParentFilePath   = '%s'", contextParentFilePath);
  DBG("  nameStructureFilePath   = '%s'", nameStructureFilePath);  
  DBG("  publicComponentFilePath = '%s'", publicComponentFilePath);
  DBG("  privateComponentFilePath: '%s'", privateComponentFilePath);
  
  while (1)
  {
    // Prepare password for parent context
    sessionData.hmac.t.size = sizeof(sessionData.hmac.t) - 2;
    if ((status = str2ByteStructure(
      parentPassword,
      &sessionData.hmac.t.size,
      sessionData.hmac.t.buffer)) != 0)
    {
      ERRFN("Error setting parent context password, returned 0x%x.", status);
      break;
    }
    
    // Load public part from file
    size = sizeof(inPublic);
    if ((status = loadDataFromFile(
      publicComponentFilePath,
      (UINT8*) &inPublic,
      (UINT16*) &size)) != 0)
    {
      ERRFN("Error loading public part, returned 0x%x.", status);
      break;
    }

    // Load private part from file
    size = sizeof(inPrivate);
    if ((status = loadDataFromFile(
      privateComponentFilePath, 
      (UINT8*) &inPrivate, 
      (UINT16*) &size)) != 0)
    {
      ERRFN("Error loading private part, returned 0x%x.", status);
      break;
    }
    
    // Load parent context from file
    if ((status = loadTpmContextFromFile(
      sysContext,
      &parentHandle,
      contextParentFilePath)) != 0)
    {
      ERRFN("Error loading parent context, returned 0x%x.", status);
      break;
    }
    
    if ((status = load(
      parentHandle,
      &inPublic,
      &inPrivate,
      nameStructureFilePath,
      keyHandle)) != 0)
    {
      ERRFN("Error loading object, returned 0x%x.", status);
      break;
    }
    
    // TODO (improvement): store context for later (re-)use
    // status = saveTpmContextToFile(sysContext, handle2048rsa, contextFile);
    
    return 1;
  }
  
  return -1;            
}


int load(
  TPMI_DH_OBJECT        parentHandle,
  TPM2B_PUBLIC         *inPublic,
  TPM2B_PRIVATE        *inPrivate,
  const char           *outFileName,
  TPM_HANDLE           *keyHandle)
{
  TPMS_AUTH_RESPONSE    sessionDataOut;
  TPMS_AUTH_COMMAND    *sessionDataArray[1];
  TPMS_AUTH_RESPONSE   *sessionDataOutArray[1];

  TSS2_SYS_CMD_AUTHS    sessionsData;
  TSS2_SYS_RSP_AUTHS    sessionsDataOut;
  
  UINT32                rval;

  TPM2B_NAME            nameExt     = { { sizeof(TPM2B_NAME)-2, } };

  sessionDataArray[0]    = &sessionData;
  sessionDataOutArray[0] = &sessionDataOut;

  // TSS2_SYS_CMD_AUTHS specifies the number of authorization areas for
  // the command and the specific authorization areas to be used.
  sessionsData.cmdAuthsCount = 1;
  sessionsData.cmdAuths      = &sessionDataArray[0];

  // TSS2_SYS_RSP_AUTHS specifies the number of authorization areas and
  // the specific response authorization areas.
  sessionsDataOut.rspAuths      = &sessionDataOutArray[0];  
  sessionsDataOut.rspAuthsCount = 1;

  // The password authorization session is a permanent entity as the
  // handle TPM_RS_PW (0x40000009). This handle is used for plaintext
  // password authorization (as opposed to HMAC authorization).
  // [Arthur & Challener 2015, p. 99]
  sessionData.sessionHandle = TPM_RS_PW;
  sessionData.nonce.t.size  = 0;

  *((UINT8 *)((void *)&sessionData.sessionAttributes)) = 0;

  rval = Tss2_Sys_Load(
     sysContext,
     parentHandle,
    &sessionsData,
     inPrivate ,
     inPublic,
     keyHandle,
    &nameExt, 
    &sessionsDataOut);
  if (rval != TPM_RC_SUCCESS)
  {
    ERRFN("Load Object Failed. TPM error code: : 0x%0x", rval);
    return -1;
  }
  
  DBGFN("Load succeeded. Loaded handle: 0x%08x", (unsigned int) *keyHandle);

  if (saveDataToFile(outFileName, (UINT8 *)&nameExt, sizeof(nameExt)))
  {
    return -2;
  }

  return 0;
}



int tpm20w_readPublic(
  const TPMI_DH_OBJECT   objectHandle,
  EC_KEY               **ecKey
)
{
  BIGNUM              *x;
  BIGNUM              *y;
  TPM2B_PUBLIC         key = { { 0, } };  
  TPMS_AUTH_RESPONSE   sessionDataOut;
  TSS2_SYS_RSP_AUTHS   sessionsDataOut;
  TPMS_AUTH_RESPONSE  *sessionDataOutArray[1];
  TPM2B_NAME           name          = { { sizeof(TPM2B_NAME)-2, } };
  TPM2B_NAME           qualifiedName = { { sizeof(TPM2B_NAME)-2, } };
  UINT32               status;

  sessionDataOutArray[0] = &sessionDataOut;
  sessionsDataOut.rspAuths = &sessionDataOutArray[0];
  sessionsDataOut.rspAuthsCount = 1;

  if ((status = Tss2_Sys_ReadPublic(
     sysContext,
     objectHandle,
     0,
    &key,
    &name,
    &qualifiedName,
    &sessionsDataOut
  )) != TPM_RC_SUCCESS)
  {
    ERRFN("TPM2_ReadPublic error: status = 0x%0x", status);
    return -1;
  }
    
  x = BN_bin2bn(
    key.t.publicArea.unique.ecc.x.t.buffer,
    key.t.publicArea.unique.ecc.x.t.size,
    NULL);
  y = BN_bin2bn(
    key.t.publicArea.unique.ecc.y.t.buffer,
    key.t.publicArea.unique.ecc.y.t.size,
    NULL);
    
  DBGFN("len(X) = 0x%x", key.t.publicArea.unique.ecc.x.t.size);

  *ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  // Specify the named curve name instead of all parameters explicitly
  // because in OpenSSL version < 1.1 explicit form is default).
  EC_KEY_set_asn1_flag(*ecKey, OPENSSL_EC_NAMED_CURVE);
  EC_KEY_set_public_key_affine_coordinates(*ecKey, x, y);
  
  return 0;
}
