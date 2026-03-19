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
static inline struct iphdr *extract_ip_header(unsigned char *payload, unsigned int payload_len);
static inline struct tcphdr *extract_tcp_header(unsigned char *payload, unsigned int payload_len, unsigned int iphdr_len);
static inline unsigned char *extract_application_data(unsigned char *payload, unsigned int payload_len, unsigned int iphdr_size, unsigned int tcphdr_size);



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

  signal(SIGINT, signals_handler);
  signal(SIGABRT, signals_handler);
  signal(SIGTERM, signals_handler);
  signal(SIGQUIT, signals_handler);
  signal(SIGSEGV, signals_handler);
  signal(SIGFPE, signals_handler);

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

  struct nfqnl_msg_packet_hdr *ph; 
  unsigned char *payload;
  unsigned int payload_len;
  uint32_t id;
  struct iphdr *ip_header;
  unsigned int iphdr_size;
  struct tcphdr *tcp_header;
  unsigned int tcphdr_size;
  unsigned char *application_payload;
  unsigned int application_payload_size;

  ph = nfq_get_msg_packet_hdr(nfa);
  id = ntohl(ph->packet_id);

  payload_len = nfq_get_payload(nfa, &payload);
  printf("Packet data: ID=%u, %d bytes \n", id, payload_len);

  ip_header = extract_ip_header(payload, payload_len);
  iphdr_size = ip_header->ihl << 2; 

  if(ip_header->protocol == IPPROTO_TCP){
    tcp_header = extract_tcp_header(payload, payload_len, iphdr_size);
    printf("TCP packet detected! Source port: %d, Destination port: %d \n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
    tcphdr_size = tcp_header->doff << 2;

    application_payload = extract_application_data(payload, payload_len, iphdr_size, tcphdr_size);
    application_payload_size = payload_len - iphdr_size - tcphdr_size;

    //SSL/TLS handshake message

    if(application_payload != NULL &&application_payload[0] == 0x16 && application_payload[1] == 0x03 && (application_payload[2] == 0x01 || application_payload[2] == 0x02 || application_payload[2] == 0x03)){
      printf(ANSI_COLOR_GREEN "SSL/TLS handshake packet detected! \n" ANSI_COLOR_RESET);
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    //SSL/TLS data message
    if(application_payload != NULL && application_payload[0] == 0x17 && application_payload[1] == 0x03 && (application_payload[2] == 0x01 || application_payload[2] == 0x02 || application_payload[2] == 0x03)){
      printf(ANSI_COLOR_GREEN "SSL/TLS data packet detected! \n" ANSI_COLOR_RESET);
      if(application_payload_size > 0){
        printf("Printing of the data \n");
        print_application_data(application_payload, application_payload_size);
      }

      //sveglio il thread che modifica il pacchetto, ricalcola la checksum, lo invia al server, avvia il timer, attende risposta server, all'arrivo stoppa il timer ed inoltra il pacchetto al client
      //modify a packet byte, send to server and start the clock
      //alterate_packet()

      //send_modufied_packet()
      
      //drop packet
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
  } 

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//function to extract the IP header from the packet payload
static inline struct iphdr *extract_ip_header(unsigned char *payload, unsigned int payload_len){
  struct iphdr *ip_header;
  if(payload_len < sizeof(struct iphdr)){
    fprintf(stderr, "Payload too small to contain an IP header! \n");
    return NULL;
  }
  ip_header = ((struct iphdr *)payload);

  return ip_header;
}

//function to extract the TCP header from the packet payload
static inline struct tcphdr *extract_tcp_header(unsigned char *payload, unsigned int payload_len, unsigned int iphdr_len){
  struct tcphdr *tcp_header;
  if(payload_len < (iphdr_len + sizeof(struct tcphdr))){
    fprintf(stderr, "Payload too small to contain a TCP header! \n");
    return NULL;
  }
  tcp_header = ((struct tcphdr *)(payload + iphdr_len));

  return tcp_header;
}

//function to extract the application data from the packet payload
static inline unsigned char *extract_application_data(unsigned char *payload, unsigned int payload_len, unsigned int iphdr_size, unsigned int tcphdr_size){
  unsigned char *application_data;
  if((payload_len <= (iphdr_size + tcphdr_size))){
    fprintf(stderr, "Payload too small to contain application data! \n");
    return NULL;
  }

  application_data = ((char *)payload + iphdr_size + tcphdr_size);
  return application_data;
}

//0 -> ssl handshake, 1 --> ssl/tls data packet, 
int analyze_application_data(unsigned char *payload, int payload_len){

}

/*
  devo tenere traccia di che byte utilizzare e di quale byte modificare
  es: byte 0x00 in ultima pos, poi 0x01, poi 0x02, ecc... fino a 0xff, poi ricomincio da 0x01
  (il byte che ha il minore tempo diu risposta è quello corretto)
*/


void alterate_packet(unsigned char *payload, unsigned int payload_len){

}


void send_modified_packet(){

}

void start_timer(){


}


void stop_timer(){

}