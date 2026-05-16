#ifndef UTILITY_H
#define UTILITY_H

#include <stdbool.h>
#include <stdint.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define BOLD_GREEN "\033[1;32m"

#define L_SIZE 10

typedef unsigned char Byte;

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

//struct to pass the measurements to the python script for the last and penultimate bytes attack
struct first_attack_result{
  int pos_byte; //posizione del byte all'interno del cookie che sto provando ad indovinare
  //matrice che contiene i tempi misurati (65536 righe e L colonne, per ogni possibile valore del byte modificato)
  int64_t time_meas[65536][L_SIZE];  //time measurements matrix
};

//struct to pass the measurements to the python script for the penultimate byte attack
struct attack_result{

  int64_t time_meas[256][L_SIZE];
};


char *delete_char(char *str, char c);
void signals_handler(int signal); //function to handle the SIGINT signal, to restore the default network settings when the user presses CTRL+C
void print_application_data(Byte *application_data, unsigned int application_data_size);
void catch_signals();
bool check_data_length(Byte *data, unsigned int data_len);
void print_data_blocks(Byte *data, unsigned int data_len);
void print_blocks(Byte *data, unsigned int data_len);
void print_tls_header(Byte *data);
Byte *make_mask(int block_pos, int byte_pos, const Data_packet *data_packet);
Byte *make_mask_first_bytes(int block_pos, const Data_packet *data_packet);
Byte *xor_block(Byte *block1, Byte *block2, unsigned int len);
void modify_last_bytes(Data_packet *data_packet, int block_pos, int val_penultimate_byte, int val_last_byte);

char *get_server_interface(const char *server_ip, const int server_port);



#endif