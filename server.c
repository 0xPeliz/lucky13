#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DIM_BUFFER 1024
#define port 5000

void init_openssl();
SSL_CTX *setup_ssl_context();

int main(int argc, char *argv[]) {

  init_openssl();
  SSL_CTX *ctx = setup_ssl_context();
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);
  int clientfd;
  SSL *ssl;
  char buffer[DIM_BUFFER];

  printf("Avvio del server sulla porta %d...\n", port);

  if (ctx == NULL) {
    perror("SSL context initialization error");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
    perror("Certificate file error");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
    perror("Private key file error");
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    perror("Private key does not match the certificate public key");
    SSL_CTX_free(ctx);
    exit(EXIT_FAILURE);
  }

  printf("SSL context initialized successfully \n");

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(port);

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("Binding error");
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, 20) < 0) {
    perror("Listening error");
    exit(EXIT_FAILURE);
  }

  // accettazione delle connessioni
  while (1) {
    clientfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
    if (clientfd < 0) {
      perror("Accept error");
      continue;
    }
    printf("Connection accepted from %s:%d\n", inet_ntoa(client_addr.sin_addr),
           ntohs(client_addr.sin_port));
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, clientfd);
    if (SSL_accept(ssl) <= 0) {
      perror("SSL accept error");
      ERR_print_errors_fp(stderr);
      SSL_free(ssl);
      close(clientfd);
      continue;
    }
    printf("SSL/TLS connection established with %s:%d\n",
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // SSL_read(ssl, buffer, DIM_BUFFER);

    const char *response = "Hello, World!";

    SSL_write(ssl, response, strlen(response));

    // qui dovrei poi ricevere il cookie dal client
  }

  // per ogni accettazione viene creato un Oggetto SSL (SSL *ssl), si attacca il
  // file descriptor e si esegue SSL_accept() per stabilire la connessione
  // SSL/TLS.

  // utilizzare SSL_read() e SSL_write() per inviare e ricevere dati con il
  // client.

  printf("Terminazione del server...\n");

  close(sockfd);
  return 0;
}

void init_openssl() {
  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
}

SSL_CTX *setup_ssl_context() {
  const SSL_METHOD *method = TLSv1_2_server_method();
  SSL_CTX *ctx = SSL_CTX_new(method);

  if (!ctx) {
    perror("SSL_CTX_Nex error");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_set_cipher_list(ctx, "AES128-SHA:AES256-SHA") <= 0) {
    perror("SSL_CTX_set_cipher_list errorr");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

  return ctx;
}
