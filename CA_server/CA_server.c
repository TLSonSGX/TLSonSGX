#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string>


char goodMeasurement[128]= "sha1:1de086c120ee73358c468f29545af52e4e676bec";

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "rootca-cert.pem", SSL_FILETYPE_PEM) < 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "rootca-key.pem", SSL_FILETYPE_PEM) < 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}



int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;
    char buf1[2048];
    char buf2[2048];
    int bytes;

    

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
	printf("Client connect\n");
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);

        }
        else {
        bytes = SSL_read(ssl, buf1, sizeof(buf1));        /* get reply & decrypt */
        buf1[bytes] = 0;
        //printf("1st Message Received from client: \"%s\"\n", buf1);
	char verdict[4];
	using namespace std;
	string strbuf(buf1);
	string headbuf(strbuf.substr(0,3));
	if (headbuf=="IMA")
	{
		std::string recv_measure(strbuf.substr(3,sizeof(buf1)-3));
		//printf("Recv measurement is %s\n", recv_measure.c_str());
		if(recv_measure==goodMeasurement)
        		{
               		strcpy(verdict, "MOK");
			
			//printf("Verdict is %s\n", verdict);
			SSL_write(ssl, verdict, 4);
			int bytes2 = 0;
			while (!strcmp(buf2,"")){
	        		bytes2 = SSL_read(ssl, buf2, sizeof(buf2));        /* get reply & decrypt */
       	        		buf2[bytes2] = 0;
        			//printf("2nd Meassage Received from client: \"%s\"\n", buf2);
			} //while
		
		FILE *req_file;
		char current_dir[1024];
		getcwd(current_dir,sizeof(current_dir));
		std::string current_dir_s(current_dir);
		std::string req_file_q=current_dir_s+"/sc-req.pem";
		req_file = fopen(req_file_q.c_str(), "wb");
		fwrite(buf2, sizeof(buf2),1, req_file);
		fclose(req_file);
		system("openssl ca -batch -passin pass:khalid123 -config openssl.cnf -out sc-cert.pem -infiles sc-req.pem");

		FILE *cert_file;
		char *cert_buf;
		std::string cert_file_q=current_dir_s+"/sc-cert.pem";	
		cert_file= fopen(cert_file_q.c_str(), "rb");
		long cert_size;
		fseek(cert_file,0,SEEK_END);
		cert_size=ftell(cert_file);
		rewind(cert_file);
		cert_buf=(char*) malloc(sizeof(char)*cert_size);	
		size_t actual_len=fread(cert_buf, sizeof(char),cert_size, cert_file);
		//printf("Generated Certificate to be sent is %s\n", cert_buf);	
		SSL_write(ssl, cert_buf, cert_size);
		free(cert_buf);

	
	        } else // verdict is NOK
                        {
                        strcpy(verdict, "NOK");
			//printf("Verdict is %s\n", verdict);
	                SSL_write(ssl, verdict, 4);
                }

	} //if headbuf
        } //else SSL_accept

        SSL_free(ssl);
        close(client);
    } //while

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}

