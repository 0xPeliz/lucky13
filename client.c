#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

SSL_CTX *setup_ssl_context();
int initialize_connection(const char *server_ip, int port);
int do_single_request(const char *server_ip, int port, SSL_CTX *ctx); 
void sendRequests(const char *server_ip, int port, SSL_CTX *ctx); // funzione per mandare dati al server
int sendCookie(SSL *ssl);

int main(int argc, char *argv[]) {
  // indirizzo del server
  /*
  if(argc != 2){
      perror("Missing server address argument");
      exit(EXIT_FAILURE);
  }

  char *server_ip = argv[1];
  */

  SSL_CTX *ctx = setup_ssl_context();

  if (ctx == NULL) {
    perror("SSL context initialization error");
    exit(EXIT_FAILURE);
  }

  sendRequests("127.0.0.1", 5000, ctx); 

  /*
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd); */
  SSL_CTX_free(ctx);

  return 0;
}

SSL_CTX *setup_ssl_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

  if (!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ctx, 4);

  return ctx;
}

//function to initialize the connections, SSL and TCP
int initialize_connection(const char *server_ip, int port) {
  struct sockaddr_in server_addr;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
    perror("Invalid address");
    exit(EXIT_FAILURE);
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Connection error");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

//function to send a single request to the server and receive the response 
int do_single_request(const char *server_ip, int port, SSL_CTX *ctx){

  int result = -1;
  char buffer[1024];  
  int sockfd = initialize_connection(server_ip, port);
  SSL *ssl = SSL_new(ctx);


  if (ssl == NULL) {
    perror("SSL initialization error");
    exit(EXIT_FAILURE);
  }

  SSL_set_fd(ssl, sockfd);

  if (SSL_connect(ssl) <= 0) {
    perror("SSL connection error");
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    exit(EXIT_FAILURE);
  }

  //send the cookie
  //sendData();

  ssize_t n = SSL_read(ssl, NULL, 0);

  if (n > 0){
    result = 1;
    buffer[n] = '\0';
  }else{

  }

  SSL_free(ssl);
  close(sockfd);

  return result;
}

//function to send data to the server in a loop, calling do_single_request for each request
void sendRequests(const char *server_ip, int port, SSL_CTX *ctx) {

  int sockfd;
  SSL *ssl;
  char buffer[1024];

  while (1) {
    do_single_request(server_ip, port, ctx);
  }

}

//function to send and receive data
int sendCookie(SSL *ssl) {

  int result = -1;

  // va prevista la codifica in base64 del cookie e la generazione casuale di

  return result;
}
