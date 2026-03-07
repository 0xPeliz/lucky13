#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

SSL_CTX *setup_ssl_context();

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

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(5000);

  if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
    perror("Invalid address");
    exit(EXIT_FAILURE);
  }

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sockfd);

  if (SSL_connect(ssl) <= 0) {
    perror("SSL connection error");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

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
