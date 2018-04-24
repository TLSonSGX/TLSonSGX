/*
 * Copyright (c) 2015 Cesanta Software Limited
 * All rights reserved
 * This software is dual-licensed: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. For the terms of this
 * license, see <http://www.gnu.org/licenses/>.
 *
 * You are free to use this software under the terms of the GNU General
 * Public License, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * Alternatively, you can license this software under a commercial
 * license, as set out in <http://cesanta.com/>.
 */
#ifdef __cplusplus
 extern "C" {
#endif

#ifndef POLARSSL_SUPPORT_HEADER_INCLUDED
#define POLARSSL_SUPPORT_HEADER_INCLUDED

#include "mbedtls/ssl.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"


#define SSL_ERROR_WANT_READ MBEDTLS_ERR_SSL_WANT_READ
#define SSL_ERROR_WANT_WRITE MBEDTLS_ERR_SSL_WANT_WRITE
#define SSL_AD_CLOSE_NOTIFY MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY

#define X509 mbedtls_x509_crt
#define X509_NAME mbedtls_x509_name


#define SSL_VERIFY_PEER 1
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 2
#define SSL_VERIFY_NONE                 0x00

// Need to be reviewed
# define SSL_ERROR_NONE                  0
# define SSL_ERROR_SSL                   1
# define SSL_ERROR_WANT_X509_LOOKUP      4
# define SSL_ERROR_SYSCALL               5/* look at error stack/return
                                           * value/errno */
# define SSL_ERROR_ZERO_RETURN           6
# define SSL_ERROR_WANT_CONNECT          7
# define SSL_ERROR_WANT_ACCEPT           8

# define SSL_NOTHING            1
# define SSL_WRITING            2
# define SSL_READING            3

# define SSL_OP_NO_SSLv2                                 0x00000000U
# define SSL_OP_NO_SSLv3                                 0x02000000U
# define SSL_OP_NO_TLSv1                                 0x04000000U
# define SSL_OP_NO_TLSv1_2                               0x08000000U
# define SSL_OP_NO_TLSv1_1                               0x10000000U
# define SSL_OP_NO_TLSv1_3                               0x20000000U

/*
 * SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER is not used at the moment.
 * see SSL_CTX_set_mode function implementation
 */
#define SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER 1
#define SSL_MODE_ENABLE_PARTIAL_WRITE 0x00000001U
#define SSL_SESS_CACHE_OFF                      0x0000

typedef struct ssl_method {
  int endpoint_type;
  int ssl_maj_ver;
  int ssl_min_ver;
} SSL_METHOD;

typedef struct ps_ssl_ctx {
  /* Own cert & private key */
  mbedtls_x509_crt cert;
  mbedtls_pk_context pk;
  /* CA certs */
  mbedtls_x509_crt CA_cert;
  /* SSL_VERIFY_REQUIRED in this implementation */
  int authmode;
  /* endpoint details */
  SSL_METHOD* ssl_method;
} SSL_CTX;

typedef struct ps_ssl {
  mbedtls_ssl_context cntx;
  /* last SSL error. see SSL_get_error implementation. */
  int last_error;
  /* associated socket */
  int fd;
  /* parent context (for debug purposes) */
  SSL_CTX* ssl_ctx;
} SSL;

int SSL_read(SSL *ssl, void *buf, int num);
int SSL_write(SSL *ssl, const void *buf, int num);
int SSL_get_error(const SSL *ssl, int ret);
int SSL_want(const SSL *ssl);
int SSL_connect(SSL *ssl);
int SSL_set_fd(SSL *ssl, int fd);
int SSL_accept(SSL *ssl);
int SSL_library_init();
void SSL_load_error_strings(); 
SSL_METHOD* SSLv23_client_method();
SSL_METHOD* SSLv23_server_method();
SSL *SSL_new(SSL_CTX *ctx);
void SSL_free(SSL *ssl);
X509 *SSL_get_peer_certificate(SSL *ssl);
X509_NAME *X509_get_subject_name(X509 *cert);
char *X509_NAME_oneline(X509_NAME *subject, char *buf, int size);
void X509_free(X509 *cert);

void SSL_CTX_free(SSL_CTX *ctx);
void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, void* reserved);
long SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
SSL_CTX *SSL_CTX_new(SSL_METHOD* ssl_method);

int SSL_get_verify_mode(SSL *ssl);
extern int SSL_get_state(SSL *ssl);
int SSL_CTX_set_cipher_list(SSL_CTX *ctx, const char *str);
long SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode);
int SSL_CTX_check_private_key(const SSL_CTX *ctx);
long SSL_CTX_set_options(SSL_CTX *ctx, long options);
int SSL_shutdown(SSL *ssl);
void SSL_CTX_set_tmp_dh_callback(SSL_CTX *ctx, void* reserved_for_cb);
void SSL_set_msg_callback(SSL_CTX *ctx, void* reserved_for_cb);
void SSL_set_msg_callback_arg(SSL_CTX *ctx, void *arg);

#endif

#ifdef __cplusplus  
} // extern "C"  
#endif
