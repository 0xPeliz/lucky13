#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>


extern char ip_client[INET_ADDRSTRLEN];
extern char ip_server[INET_ADDRSTRLEN];
extern int port_server;
extern char network_config;
extern char op_mode;

void setup_network_interception();
void restore_network_default();
void set_ipforwarding(int setting);
int handle_tcp_packet(unsigned char *payload, int payload_len);
int handle_tls_data(unsigned char *application_payload, unsigned int application_payload_size);

void config_localhost_architecture();
void config_lan_architecture();
void config_internet_architecture();

void get_network_info(char *local_ip, char *gateway_ip);
pid_t arp_spoofing(const char *tagert_ip, const char *host_ip);

#endif