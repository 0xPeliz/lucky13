#include "../include/network.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdbool.h>
#include <sys/socket.h>

//function to set a personalized iptables configuration on the client to receive packets
void setup_network_interception() {
  char cmd[256];
  char port[6];

  snprintf(port, sizeof(port), "%d", port_server);

  if(network_config == 'l'){
    snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
  }else if(network_config == 'n' || network_config == 'i'){
    //snprintf(cmd, sizeof(cmd), "iptables -A FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    set_ipforwarding(1);
  }

  system(cmd);
}

//function to restore the default settings of iptables
void restore_network_default() {

  char cmd[256];
  char port[6];
  snprintf(port, sizeof(port), "%d", port_server);

  if(network_config == 'l'){
    snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
  }else if(network_config == 'n' || network_config == 'i'){
    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    set_ipforwarding(0);
  }

  system(cmd);
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

void config_localhost_architecture(){
  printf("Sono dentro alla configurazione dell'architettura per localhost \n");
}


void config_lan_architecture(){
  printf("Sono dentro alla configurazione dell'architettura lan \n");
}


void config_internet_architecture(){
  printf("Sono dentro alla configurazione dell'architettura internet \n");

}

pid_t arp_spoofing(const char *target_ip, const char *host_ip){
  pid_t pid = fork();

  if(pid == -1){ //error
    perror("Fork error!");
    exit(EXIT_FAILURE);
  }else if(pid == 0){ //child
    int devnull = open("/dev/null", O_WRONLY);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
    execl("/usr/sbin/arpspoof", "arpspoof", "-i", "eth0", "-t", target_ip, host_ip, NULL);
    perror("Arp spoofing executing error");
    exit(EXIT_FAILURE);
  }

  return pid;
}


void get_network_info(char *local_ip, char *gateway_ip){
  FILE *fp;
  char line[256];
  char iface[IFNAMSIZ];
  unsigned long destination, gateway;
  bool gateway_found = false;
  int sockfd;
  struct ifreq ifr;
  struct in_addr gateway_addr;

  fp = fopen("/proc/net/route", "r");

  if(fp == NULL){
    perror("Error in opening proc/net/route file");
    return;
  }

  fgets(line, sizeof(line), fp);

  while(fgets(line, sizeof(line), fp) && !gateway_found){
    if(sscanf(line, "%15s %lx %lx", iface, &destination, &gateway) == 3){
      if(destination == 0x00000000){
        gateway_addr.s_addr = gateway;
        strcpy(gateway_ip, inet_ntoa(gateway_addr));
        gateway_found = true;
      }
    }
  }

  fclose(fp);

  if(!gateway_found){
    perror("Gateway not found!");
    return;
  }

  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if(sockfd < 0){
    perror("Error in creating socket!");
    exit(EXIT_FAILURE);
  }
  
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

  if(ioctl(sockfd, SIOCGIFADDR, &ifr) == 0){
    struct sockaddr_in *ipaddr = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(local_ip, inet_ntoa(ipaddr->sin_addr));
  }else{
    perror("Errore in ioctl (Impossibile ricavare IP locale)");
  }

  close(sockfd);

}