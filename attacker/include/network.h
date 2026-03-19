#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>

extern char *ip_client;
extern char *ip_server;
extern int port_server;
extern char network_config;
extern char op_mode;

void setup_network_interception();
void restore_network_default();
void set_ipforwarding(int setting);
int handle_tcp_packet(unsigned char *payload, int payload_len);
int handle_tls_data(unsigned char *application_payload, unsigned int application_payload_size);

#endif