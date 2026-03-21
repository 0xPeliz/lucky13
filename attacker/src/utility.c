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
