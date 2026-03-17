#define _GNU_SOURCE
#include "../include/utility.h"
#include "../include/network.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

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

void extract_mode();
void extract_network_config();
void do_localhost_attack();
void do_lan_attack();
void do_internet_attack();
void arp_spoofing(char *ip);

// network
void setup_nfq(struct nfq_handle **h, struct nfq_q_handle **qh);
void intercept_packets();

#define DIM_PAGE 4096

char *ip_client = "127.0.0.1"; 
char *ip_server = "127.0.0.1";
int port_server = 5000;
char network_config;
char op_mode;

static int packet_verdict_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

int main(int argc, char *argv[]) {

  if (argc < 3) {
    perror("Missing arguments! \n");
    return 0;
  }

  // -d (creazione dstaset), -a (attaccante vero e proprio)
  if(argv[1][0] == '-'){
    op_mode = argv[1][1];
  }

  if(argv[2][0] == '-'){
    network_config = argv[2][1];
  }
  
  printf("Operation mode: %c. Network config: %c \n", op_mode, network_config);

  extract_mode();
  extract_network_config();

  signal(SIGINT, sigint_handler);

  // selecting the operation mode
  // -m --> LocalHost
  // -l --> client and server in the same LAN
  // -i --> client in the same LAN and server outside

  printf("Starting MITM proxy \n");

  setup_network_interception();
  intercept_packets();

  return 0;
}

//function to extrract the operating mode by operating mode parameter
void extract_mode() {

  //op_mode = delete_char(op_mode, '-');

  // secruity check about number of char
  /*
  if (strlen(op_mode) > 1) {
    perror("Too many chars in the mode flag! \n");
    exit(EXIT_FAILURE);
  }*/
  
  switch (op_mode) {
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

//function to extrract the network configuration by network configuration parameter
void extract_network_config() {
  //network_config = delete_char(network_config, '-');

  /*
  if (strlen(network_config) > 1) {
    fprintf(stderr, "Too many chars in the network_config flag! \n");
    exit(EXIT_FAILURE);
  }*/

  switch (network_config) {
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

//function to initialize nfq (NFQUEUE)
void setup_nfq(struct nfq_handle **h, struct nfq_q_handle **qh){

  *h = nfq_open();
  int fd;

  if(!(*h)){
    perror("Error in the NFQUEUE opening! \n");
    exit(EXIT_FAILURE);
  }

  *qh = nfq_create_queue(*h, 0, &packet_verdict_handler, NULL);

  if(!(*qh)){
    perror("Error in the NFQUEUE creation! \n");
    exit(EXIT_FAILURE);
  }

  if(nfq_set_mode(*qh, NFQNL_COPY_PACKET, 0xffff) < 0){
    perror("Error in the NFQUEUE mode setting! \n");
    exit(EXIT_FAILURE);
  }

}

//forse da spostare in network.c
void intercept_packets() {

  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  int fd;
  int rcv;
  char buffer[DIM_PAGE] __attribute__((aligned));

  setup_nfq(&h, &qh);

  fd = nfq_fd(h);

  do{
    rcv = recv(fd, buffer, sizeof(buffer), 0);
    if(rcv > 0){
      nfq_handle_packet(h, buffer, rcv);
    }
  }while(rcv > 0);

}

static int packet_verdict_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){

  struct nfqnl_msg_packet_hdr *ph; //info about received packet
  unsigned char *payload;
  int payload_len;
  uint32_t id;
  
  struct iphdr *iph;

  unsigned int iphdr_size;
  struct tcphdr *tcp_header;

  ph = nfq_get_msg_packet_hdr(nfa);
  id = ntohl(ph->packet_id);

  //controllo se sono pacchetti del three way handshake, non hanno payload

  payload_len = nfq_get_payload(nfa, &payload);
  printf("Packet data: ID=%u, %d bytes \n", id, payload_len);

  iph = ((struct iphdr *)payload);
  iphdr_size = iph->ihl << 2; 

 /*
  for(int i=0; i<payload_len; i++){
    printf("%02x ", payload[i]);
  } */

  printf("Iniziale pyaload: %02x \n", payload[0]);

  if(iph->protocol == IPPROTO_TCP){
    tcp_header = (struct tcphdr *)(payload + iphdr_size);
    printf("TCP packet detected! Source port: %d, Destination port: %d \n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
  }
  
  //payload contiene il pacchetto raw grezzo a partire dall'header IP in su (devo quindi valutare la parte applicativa, che si trova dopo tcp)
  if (payload_len >= 5 && payload[0] == 0x16 && payload[1] == 0x03 && (payload[2] == 0x01 || payload[2] == 0x02 || payload[2] == 0x03)) {
    printf("SSL/TLS handshake packet detected! \n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
  }

  //se il pacchetto non appartiene ne al 3 way handshake ne all'instauramento della connessione SSL, allora altero il byte della data posizione e di un dato valore
  //modify_packet_byte();

  if(payload_len > 0 && memmem(payload, payload_len, "BLOCKED", 7) != NULL){
    printf("PACKET DROP \n");
    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  }

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}
