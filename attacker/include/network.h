#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/time.h>
#include <time.h>


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

void get_local_address(const char *server_ip, const int server_port, struct sockaddr_in *local_addr);
pcap_t *setup_pcap(const char *server_interface, const char *server_ip, const int server_port);
struct timespec get_server_response_time(pcap_t *handle);

void flush_pcap_buffer(pcap_t *handle);

#endif