#include "../include/network.h"

void setup_network_interception() {
  char cmd[256];
  char port[6];

  snprintf(port, sizeof(port), "%d", port_server);

  if(network_config == 'm'){
    snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
  }else if(network_config == 'l' || network_config == 'i'){
    snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    set_ipforwarding(1);
  }

  system(cmd);

  printf("Sono alla fine della funzione setup_network_interception \n");
}


void restore_network_default() {

  char cmd[256];
  char port[6];
  snprintf(port, sizeof(port), "%d", port_server);

  if(network_config == 'm'){
    snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
  }else if(network_config == 'l' || network_config == 'i'){
    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    set_ipforwarding(0);
  }

  system(cmd);
  printf("Sono alla fine della funzione restore_network_default \n");
}

//function to set IP forwarding, necessary for MITM proxy outiside localhost
void set_ipforwarding(int setting){
  int fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY);

  if(fd == -1){
    perror("Error in opening ipv4 file to set forwarding \n");
    exit(EXIT_FAILURE);
  }

  if(setting == 1){
    if(write(fd, "1", 1) == -1){
      perror("Error writing the ip_forward file! \n");
      exit(EXIT_FAILURE);
    }else{
      printf("IP FORWARDING ENABLED! \n");
    }
  }else{
    if(write(fd, "0", 1) == -1){
      perror("Error ");
    }else{
      printf("IP FORWARDING DISABLED! \n");
    }
  }

  close(fd);
}
