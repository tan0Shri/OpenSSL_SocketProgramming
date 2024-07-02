#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL  -1

//Global Variables
SSL *ssl;
char name[256];


void *ReceiveMessages(void *arg);

int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        exit(EXIT_FAILURE);
    }

    return sd;
}

SSL_CTX* InitCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void ShowCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}

void *ReceiveMessages(void *arg) {
    char buf[1024];
    int bytes;

    while (1) {
        bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("\n%s\n", buf);
        } else {
            break;
        }
    }
    return NULL;
}

int main() {
    SSL_CTX *ctx;
    int server;
    pthread_t recv_thread;
    char buf[1024];

    char hostname[] = "127.0.0.1";
    char portnum[] = "5000";
    
    // Get the user's name
    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);
    name[strcspn(name, "\n")] = 0;  // remove newline character
    
    // Initialize SSL context
    ctx = InitCTX();
    // Establish a TCP connection
    server = OpenConnection(hostname, atoi(portnum));
    // Create new SSL connection state
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);
    
    // Perform SSL/TLS handshake with server
    if (SSL_connect(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);  // Get server's certificate
        
    	printf("Type message and press enter to send (\"exit\" to quit): ");
        pthread_create(&recv_thread, NULL, ReceiveMessages, NULL);
        while (1) {
            char line[1024] = " ";
           
            fgets(line, sizeof(line), stdin);

            sprintf(buf, "%s", line);
            buf[strcspn(buf, "\n")] = 0;  // remove newline character

            if (strcmp(buf, "exit") == 0) {
                break;
            }

            char buffer[1280];
            sprintf(buffer,"%s:%s", name, buf);
            SSL_write(ssl, buffer, strlen(buffer));
        }
        pthread_cancel(recv_thread);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server);
        SSL_CTX_free(ctx);
    }

    return 0;
}

