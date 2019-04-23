#ifndef _TPM20W_H_
#define _TPM20W_H_

#include <stdio.h>
#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>
#include <openssl/ec.h>
#include "common.h"

#ifdef DEBUG

#define DBG(x, ...)	     fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define DBGFN(x, ...)    fprintf(stderr, "%s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#else

#define DBG(x, ...)
#define DBGFN(x, ...)
#define ERRFN(x, ...)    fprintf(stderr, "Error in %s:%d %s: " x "\n", __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__)

#endif

int tpm20w_loadSigningKey(
  const char  *parentFilePath,
  const char  *parentPassword,
  const char  *objectFilePath,
  TPM_HANDLE  *keyHandle
);

int tpm20w_signEcdsaWithSha256(
  const unsigned char  *digestBytes,
  int                   digestLen,
  TPMI_DH_OBJECT        keyHandle,
  const char           *keyPassword,
  TPMT_SIGNATURE       *signature
);

int tpm20w_readPublic(
  const TPMI_DH_OBJECT    objectHandle,
  EC_KEY                **ecKey
);

#endif
