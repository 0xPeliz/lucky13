#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

extern char *ip_client;
extern char *ip_server;
extern int port_server;
extern char network_config;
extern char op_mode;

void setup_network_interception();
void restore_network_default();
void set_ipforwarding(int setting);

#endif