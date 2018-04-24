#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/compat-1.3.h"


typedef struct ssl_method {
  int endpoint_type;
  int ssl_maj_ver;
  int ssl_min_ver;
} SSL_METHOD;

typedef struct ps_ssl_ctx {
  /* Own cert & private key */
  x509_crt cert;
  pk_context pk;
  /* CA certs */
  x509_crt CA_cert;
  /* SSL_VERIFY_REQUIRED in this implementation */
  int authmode;
  /* endpoint details */
  SSL_METHOD* ssl_method;
} SSL_CTX;



typedef struct ps_ssl {
  ssl_context cntx;
  /* last SSL error. see SSL_get_error implementation. */
  int last_error;
  /* associated socket */
  int fd;
  /* parent context (for debug purposes) */
  SSL_CTX* ssl_ctx;
} SSL;

#if defined(__cplusplus)
extern "C" {
#endif


#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */

