/* ssl_client.c
 *
 * Copyright (c) 2000 Sean Walton and Macmillan Publishers.  Use may be in
 * whole or in part in accordance to the General Public License (GPL).
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
*/

/*****************************************************************************/
/*** ssl_client.c                                                          ***/
/***                                                                       ***/
/*** Demonstrate an SSL client.                                            ***/
/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <poll.h>
#include <stddef.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <fcntl.h> 


#include "wrapper_ssl.h"

#define FAIL    -1

/*---------------------------------------------------------------------*/
/*--- OpenConnection - create socket and connect to server.         ---*/
/*---------------------------------------------------------------------*/
int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
// set non blocking
int flags = fcntl(sd, F_GETFL, 0);
if (flags != -1) {
fcntl(sd, F_SETFL, flags | O_NONBLOCK);
printf("Non blocking set\n");
}
//
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    int error;
    error=connect(sd, (struct sockaddr *)&addr, sizeof(addr));
    if (error == EINPROGRESS)
	         {
        error = EAGAIN;
    }
//    if ( connect(sd, (struct sockaddr *)&addr, sizeof(addr)) != 0 )
//    {
//        close(sd);
//        perror(hostname);
//        abort();
//    }
    return sd;
}

/*---------------------------------------------------------------------*/
/*--- InitCTX - initialize the SSL engine.                          ---*/
/*---------------------------------------------------------------------*/
SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_load_error_strings();			/* Bring in and register error messages */
    SSL_library_init();
    method = SSLv23_client_method();		/* Create new client-method instance */
    ctx = SSL_CTX_new(method);			/* Create new context */

    if ( ctx == NULL )
    {
        abort();
    }
    return ctx;
}
/*-------------------------------------------------------*/
void loadCert(SSL_CTX* ctx, char* CAfile, char* CApath, char* Certfile, char* Keyfile)
{
printf("loadCert: Loading client certificates\n");
int result = 100;
//SSL_CTX_use_certificate_file(ctx, Certfile, 0);
//SSL_CTX_use_PrivateKey_file(ctx, Keyfile, 0);
//char *line;
// line = X509_NAME_oneline(X509_get_subject_name(&ctx->CA_cert), 0, 0);
//printf("CA Cert Subject: %s\n", line);


}
/*---------------------------------------------------------------------*/
/*--- ShowCerts - print out the certificates.                       ---*/
/*---------------------------------------------------------------------*/
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);	/* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);							/* free the malloc'ed string */
        X509_free(cert);					/* free the malloc'ed certificate copy */
    }
    else
        printf("No certificates.\n");
    printf("Debug: End of ShowCerts\n");
}

/*---------------------------------------------------------------------*/
/*--- main - create SSL context and connect                         ---*/
/*---------------------------------------------------------------------*/
int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char CAfile[]="/etc/ssl/certs/Swisscom_Root_CA_2.pem";
    char CApath[]="/etc/ssl/certs/";
    char Keyfile[]="/etc/ssl/certs/ssl-cert-snakeoil.key";
    char Certfile[]="/etc/ssl/certs/ssl-cert-snakeoil.pem";
    
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
	hostname=strings[1];
	portnum=strings[2];
    ctx = InitCTX();
//    loadCert(ctx, CAfile, CApath, Certfile, Keyfile);
//    printf("Debug: after loadCert %s\n", &ctx->CA_cert);
    server = OpenConnection(hostname, atoi(portnum));
    printf("Connection Opened\n");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    ssl = SSL_new(ctx);						/* create new SSL connection state */
    SSL_set_fd(ssl, server);				/* attach the socket descriptor */
    int connectResult = 10;
    printf("**************SSL State is %d\n", SSL_get_state(ssl));
    connectResult= SSL_connect(ssl);
    printf("Connect Result is %d\n", connectResult);
    printf("**************SSL State is %d\n", SSL_get_state(ssl));
//    if ( SSL_connect(ssl) == FAIL )			/* perform the connection */
    if (connectResult == FAIL)
	printf("Error");
    else
    {   //char *msg = "Hello???";
	char *msg =  "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
        ShowCerts(ssl);								/* get any certs */
        SSL_write(ssl, msg, strlen(msg));			/* encrypt & send message */
	printf("**************SSL State is %d\n", SSL_get_state(ssl));
	printf("Debug: Message sent: %s\n", msg);
        bytes = SSL_read(ssl, buf, sizeof(buf));	/* get reply & decrypt */
	printf("**************SSL State is %d\n", SSL_get_state(ssl));
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
	SSL_shutdown(ssl);
	printf("**************SSL State aftershutdown is %d\n", SSL_get_state(ssl));
        SSL_free(ssl);								/* release connection state */
    }
    close(server);									/* close socket */
    SSL_CTX_free(ctx);								/* release context */
}
