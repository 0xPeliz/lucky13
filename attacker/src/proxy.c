#include "../include/utility.h"
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
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

void extract_mode(char *op_mode);
void extract_network_config(char *network_config);
void do_localhost_attack();
void do_lan_attack();
void do_internet_attack();
void arp_spoofing(char *ip);

// network
void intercept_packets();

int main(int argc, char *argv[]) {

  char *network_config;
  char *op_mode;

  if (argc < 3) {
    perror("Missing arguments! \n");
    return 0;
  }

  // -d (creazione dstaset), -a (attaccante vero e proprio)
  op_mode = argv[1];
  network_config = argv[2];

  printf("Operation mode: %s. Network config: %s \n", op_mode, network_config);

  extract_mode(op_mode);
  extract_network_config(network_config);

  // selecting the operation mode
  // -m --> LocalHost
  // -l --> client and server in the same LAN
  // -i --> client in the same LAN and server outside

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
  // forse meglio spostarlo nel main
  switch (op_mode[0]) {
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

void extract_network_config(char *network_config) {
  network_config = delete_char(network_config, '-');

  if (strlen(network_config) > 1) {
    fprintf(stderr, "Too many chars in the network_config flag! \n");
    exit(EXIT_FAILURE);
  }

  switch (network_config[0]) {
  case 'm':
    printf("LocalHost network configuration selected \n");
    break;
  case 'l':
    printf("LAN network configuration selected \n");
    break;
  case 'i':
    printf("Internet network configuration selected \n");
    break;
  default:
    fprintf(stderr, "Invalid netowkr configuration flag! \n");
  }
}

void do_localhost_attack() {

  // attaccante deve mettersi in ascolto sull'interfaccia di loopback
  //
  //
}

void arp_spoofing(char *ip) {

  // chiama l'apposito tool per effettuare arp spoofing
}

void intercept_packets() {}

void setup_network_interception(char *ip_client, char *ip_server, int port_server) {
  char cmd[256];
  char port[6];

  snprintf(port, sizeof(port), "%d", port_server);

  snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);

  system(cmd);
}

void restore_network_default(char *ip_client, char *ip_server, int port_server) {

  char cmd[256];
  char port[6];
  snprintf(port, sizeof(port), "%d", port_server);

  snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);

  system(cmd);
}
