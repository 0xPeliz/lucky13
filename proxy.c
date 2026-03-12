#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Obittivi del proxy:
 * inoltrare il traffico da client a server
 *      - inoltrare il three way handshake
 *      - inoltrare l'instauramento della connessione SSL
 *      -
 *
 *      considerare il caso in cui il server si trova in una sottorete diversa
 * dalla mia ma gestito da switc
 *
 * */

char *delete_char(char *str, char c);

void extract_mode(char *op_mode);
void do_localhost_attack();
void do_lan_attack();
void do_internet_attack();
void arp_spoofing(char *ip);

int main(int argc, char *argv[]) {

  int network_config;
  char *op_mode;

  if (argc < 3) {
    perror("Missing arguments! \n");
    return 0;
  }

  // -d (creazione dstaset), -a (attaccante vero e proprio)
  op_mode = argv[1];
  network_config = strtol(argv[2], NULL, 10);

  printf("Operation mode: %s. Network config: %d \n", op_mode, network_config);

  extract_mode(op_mode);

  // selecting the operation mode
  // 1 --> LocalHost
  // 2 --> client and server in the same LAN
  // 3 --> client in the same LAN and server outside

  printf("Starting MITM proxy \n");

  return 0;
}

void extract_mode(char *op_mode) {

  op_mode = delete_char(op_mode, '-');

  // secruity check about number of char
  if (strlen(op_mode) > 1) {
    perror("Too many chars in the mode flag! \n");
    exit(EXIT_FAILURE);
  }
  //forse meglio spostarlo nel main
  switch(op_mode[0]) {
    case 'd':
      printf("Dataset creation mode selected! \n");
      break;
    case 'a':
      printf("Attack mode selected! \n");
      break;
    default:
      perror("Invalid operation mode! \n");
      exit(EXIT_FAILURE);
  }
}

void do_localhost_attack() {

  // attaccante deve mettersi in ascolto sull'interfaccia di loopback
  //
}

void arp_spoofing(char *ip) {

  // creazione del pacchetto ARP request in broadcast
}

char *delete_char(char *str, char c) {
  int i, j = 0;
  int len = strlen(str);

  for (i = 0; i < len; i++) {
    if (str[i] != c) {
      str[j] = str[i];
      j++;
    }
  }

  str[j] = '\0';

  return str;
}
