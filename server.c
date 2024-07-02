#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

#define FAIL -1
#define MAX_CLIENTS 100
#define PORT 5000
#define CERT_FILE "certificate.crt"
#define KEY_FILE "private_key.pem"

// Global variables
int server;
SSL_CTX *ctx;

typedef struct {
    SSL *ssl;
    int socket; 
} client_t;

client_t *clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


// Function declarations
int OpenListener(int port, const char *ip);
SSL_CTX* InitServerCTX(void);
void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile);
void Servlet(SSL* ssl);
void *HandleClient( void * arg);
void BroadcastMessage(const char *message, SSL *sender_ssl);
void Cleanup(int sig);

int main() {
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    const char *ip =" ";
    //if (argc >1){ ip=argv[1];}
    
    // Handle signal for clean exit
    signal(SIGINT, Cleanup);

    // Initialize SSL context
    ctx = InitServerCTX();
    
    // Load server certificates
    LoadCertificates(ctx, CERT_FILE, KEY_FILE);
    
    // Open listener socket
    server = OpenListener(PORT,ip);

    printf("Server listening on port %d\n", PORT);

    while (1) {
        client_t *cli = (client_t *)malloc(sizeof(client_t));
        SSL *ssl;
        pthread_t tid;
        int client = accept(server, (struct sockaddr*)&addr, &len);

        if (client < 0) {
            perror("Unable to accept connection");
            free(cli);
            continue;
        }

        printf("Connection from: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
         
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        cli->ssl = ssl;
        cli->socket = client;

        // Create a new thread to handle the client connection
        if (pthread_create(&tid, NULL, HandleClient, cli) != 0) {
            perror("Unable to create thread");
            close(client);
            free(cli);
        }

        // Detach the thread so that resources are freed when it finishes
        pthread_detach(tid);
    }

    close(server);
    SSL_CTX_free(ctx);
    return 0;
}


int OpenListener(int port, const char *ip) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        close(sd);
        exit(EXIT_FAILURE);
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        close(sd);
        exit(EXIT_FAILURE);
    }

    return sd;
}

SSL_CTX* InitServerCTX(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

void Servlet(SSL* ssl) {
    char buf[1124];
    int bytes;
    const char* HTMLecho = "<html><body><pre>%s</pre></body></html>\n\n"; 

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
    } else {
    	  while (1) {
            bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (bytes > 0) {
                buf[bytes] = '\0';
                printf("%s\n", buf);
                if (strcmp(buf, "exit") == 0) {
                    break;
                }
                // Broadcast message to other clients
                BroadcastMessage(buf, ssl);
            } else {
            	if(bytes<=0){
            	    printf("Connection lost from a client\n");
        	}
                ERR_print_errors_fp(stderr);
                break;
            }
        }
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void *HandleClient(void *arg) {
    client_t *cli = (client_t *)arg;
    SSL *ssl = cli->ssl;

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == NULL) {
            clients[i] = cli;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    Servlet(ssl);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] == cli) {
            clients[i] = NULL;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    close(cli->socket);
    free(cli);
    return NULL;
}

void BroadcastMessage(const char *message, SSL *sender_ssl) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; ++i) {
        if (clients[i] != NULL && clients[i]->ssl != sender_ssl) {
            SSL_write(clients[i]->ssl, message, strlen(message));
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

void Cleanup(int sig) {
    printf("Shutting down server...\n");
    close(server);
    SSL_CTX_free(ctx);
    exit(0);
}


