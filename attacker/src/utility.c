#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "../include/network.h"
#include "../include/utility.h"

// function to delete a char passed as argument
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


void signals_handler(int signal){
  printf("Termination signal received! \n");
  restore_network_default();
  exit(0);
}

//function to print application data byte of a packet
void print_application_data(unsigned char *application_data, unsigned int application_data_size){
  printf("Printing of the application data \n");
  for(int i=0;i < application_data_size; i++){
    printf("%02x ", application_data[i]);
  }
  printf("\n");
  printf("Data length: %d \n", application_data_size);

}

/*
void print_packet(Data_packet *data_packet) {
  printf("------Packet------ \n");
  printf("IP Header: \n");
  print_ip_header(data_packet->ip_header);
  printf("TCP Header: \n");
  print_tcp_header(data_packet->tcp_header);
  printf("Application Data: \n");
  print_application_data(data_packet->data, data_packet->data_len);
} */

void catch_signals(){
  signal(SIGINT, signals_handler);
  signal(SIGABRT, signals_handler);
  signal(SIGTERM, signals_handler);
  signal(SIGQUIT, signals_handler);
  signal(SIGSEGV, signals_handler);
  signal(SIGFPE, signals_handler);
}

//function to check if the data length is correct, comparing the length of the application data with the length specified in the packet header
bool check_data_length(Byte *data, unsigned int data_len){
  bool valid = false;

  if(data_len < 0 || data_len > 65535){
    return valid;
  }

  unsigned int total_data_len =(unsigned int)(data[3] << 8 | data[4]);
  printf("Total data length from the packet: %d \n", total_data_len);
  printf("Data length from the packet header: %d \n", data_len);
  if(total_data_len == data_len - 5){
    valid = true;
  }

  return valid;
}

//ONLY FOR THE ORIGINAL DATA PACKET BECAUSAE THIS FUNCTION SKIPS THE FIRST 5 POSITIONS
//function to print the data blocks of a packet, to understand how the data is structured and where to modify it
void print_data_blocks(Byte *data, unsigned int data_len){
  printf(" \n Printing of the data blocks \n");
  
  for(int i=0; i < data_len - 5; i++){
    if(i % 16 == 0){
      printf("\n B%d -> ", (i/16));
    }
    printf("%02x ", data[i+5]);
  }
  printf("\n");
}

void print_blocks(Byte *data, unsigned int data_len){
  for(int i=0; i < data_len - 5; i++){
    if(i % 16 == 0){
      printf("\n B%d -> ", (i/16));
    }
    printf("%02x ", data[i]);
  }
  printf("\n");
}

//function to perform the XOR operation between two blocks of data, to modify the packet
Byte *xor_block(Byte *block, Byte *mask, unsigned int len){

  Byte *result = (Byte *)malloc(sizeof(Byte) * len);
  int i,j = 5;

  for(i=0; i < len && j < len; i++, j++){
    result[i] = block[j] ^ mask[i];
    printf("block byte: %02x, mask byte: %02x, result byte: %02x \n", block[j], mask[i], result[i]);
  }

  return result;
}


Byte *make_mask(int block_pos, int byte_pos, const Data_packet *data_packet){

  Byte *mask = (Byte *) malloc(sizeof(Byte) * (data_packet->data_len - 5));
  int num_block = 0;
  int i;

  for(i=0; i < data_packet->data_len - 5; i++){
    if(i != 0 && i % 16 == 0){
      num_block++;
    }
    if(block_pos-1 == num_block && (i >= (num_block * 16 + byte_pos))){
      mask[i] = data_packet->data[i+5];
    }else{
      mask[i] = 0x00;
    }
  }

  return mask;
}