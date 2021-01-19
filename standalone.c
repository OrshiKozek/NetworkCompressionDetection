/*

  Author: Orshi Kozek

  Standalone Application

  This program attempts to detect network compression through sending
  TCP packets followed by a UDP packet train and a tail TCP packet.
  This is done twice, for high entropy data and low entropy data.

  To compile this program: gcc standalone.c -ljson-c -lpcap
  To run this program: ./a.out config_file.json

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string.h>           
#include <netdb.h>            
#include <sys/types.h>        
#include <sys/socket.h>       
#include <netinet/in.h>       
#include <netinet/ip.h>       
#include <netinet/tcp.h>      
#include <arpa/inet.h>        
#include <sys/ioctl.h>        
#include <bits/ioctls.h>      
#include <net/if.h>           
#include <linux/if_ether.h>   
#include <linux/if_packet.h>  
#include <net/ethernet.h>
#include <json-c/json.h>      
#include <sys/random.h>       
#include <pcap.h>            
#include <ctype.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>            

#define IP4_HDRLEN 20         // IPv4 header length
#define TCP_HDRLEN 20         // TCP header length, excludes data
#define SIZE_ETHERNET 14      // Ethernet header size

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

//the struct that stores the parsed json values from config file
struct config_info{
  char server_ip[20];
  char s_port_udp[20];
  char d_port_udp[20];
  char d_port_tcp_head[20];
  char d_port_tcp_tail[20];
  char probing_port[20];
  char udp_payload_sz[20];
  char int_measu_time[20];
  char num_udp_packets[20];
  char udp_ttl[20];
  char packet_delay[20];
};

struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t tcp_length;
};

/* Packet sniffer pseudo-Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* Packet sniffer pseudo-IP header */
struct sniff_ip {
  u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char  ip_tos;                 /* type of service */
  u_short ip_len;                 /* total length */
  u_short ip_id;                  /* identification */
  u_short ip_off;                 /* fragment offset field */
  #define IP_RF 0x8000            /* reserved fragment flag */
  #define IP_DF 0x4000            /* don't fragment flag */
  #define IP_MF 0x2000            /* more fragments flag */
  #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char  ip_ttl;                 /* time to live */
  u_char  ip_p;                   /* protocol */
  u_short ip_sum;                 /* checksum */
  struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Packet sniffer pseudo-TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;               /* source port */
  u_short th_dport;               /* destination port */
  tcp_seq th_seq;                 /* sequence number */
  tcp_seq th_ack;                 /* acknowledgement number */
  u_char  th_offx2;               /* data offset, rsvd */
  #define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
  #define TH_FIN  0x01
  #define TH_SYN  0x02
  #define TH_RST  0x04
  #define TH_PUSH 0x08
  #define TH_ACK  0x10
  #define TH_URG  0x20
  #define TH_ECE  0x40
  #define TH_CWR  0x80
  #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /* window */
  u_short th_sum;                 /* checksum */
  u_short th_urp;                 /* urgent pointer */
};

// Function prototypes
struct config_info* read_config(char* file_name, struct config_info* info);
char *allocate_strmem(int);
uint8_t *allocate_ustrmem(int);
int *allocate_intmem(int);
unsigned short checksum(unsigned short *ptr,int nbytes);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

//global variables
clock_t low_start, low_end, high_start, high_end;
pcap_t *handle;       /* packet capture handle */

//handles timeout in receiving packets
//and ends packet sniffing loop
void alarm_handler(int sig)
{
  pcap_breakloop(handle);
}


//dissect packet and calculate times
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

  static int count = 1;                   /* packet counter */
  
  /* declare pointers to packet headers */
  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  const struct sniff_ip *ip;              /* The IP header */
  const struct sniff_tcp *tcp;            /* The TCP header */

  int size_ip;
  int size_tcp;
  
  count++;
  
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(packet);
  
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  size_ip = IP_HL(ip)*4;
  if (size_ip < 20) {
    printf("   * Invalid IP header length: %u bytes\n", size_ip);
    return;
  }
  
  /* define/compute tcp header offset */
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  size_tcp = TH_OFF(tcp)*4;
  if (size_tcp < 20) {
    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    return;
  }
  
  int src_port = ntohs(tcp->th_sport);
  int dst_port = ntohs(tcp->th_dport);

  if(count == 2 && src_port == 8000 && dst_port == 5000){
    low_start = clock();
  }
  else if(count == 3 && src_port == 8001 && dst_port == 5000){
    low_end = clock();
  }
  else if(count == 4 && src_port == 8000 && dst_port == 5000){
    high_start = clock();
  }
  else if(count == 5 && src_port == 8001 && dst_port == 5000){
    high_end = clock();
  }

  return;
}

// Allocate memory for an array of chars.
char* allocate_strmem(int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t* allocate_ustrmem(int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int* allocate_intmem(int len){
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}

//reads in config information from the given file
struct config_info* read_config(char* file_name, struct config_info* info){

  //declare variables
  FILE *fp;
  char buffer[1024];

  struct json_object *parsed_json;
  struct json_object *host_ip;
  struct json_object *s_port;
  struct json_object *d_port;
  struct json_object *d_head;
  struct json_object *d_tail;
  struct json_object *tcp_port;
  struct json_object *pl_size;
  struct json_object *i_m_time;
  struct json_object *udp_num;
  struct json_object *ttl;
  struct json_object *p_delay;

  //open file for reading
  fp = fopen(file_name, "r");
  if(fp == NULL){
    perror("Couldn't open file in read_config\n");
    exit(-1);
  }

  //read file into buffer and close fd
  fread(buffer, 1024, 1, fp);
  fclose(fp);

  //parse the contents of the json file
  parsed_json = json_tokener_parse(buffer);

  //save each individual element of the json file to a json_object variable
  json_object_object_get_ex(parsed_json, "host_ip", &host_ip);
  json_object_object_get_ex(parsed_json, "s_port", &s_port);
  json_object_object_get_ex(parsed_json, "d_port", &d_port);
  json_object_object_get_ex(parsed_json, "d_head", &d_head);
  json_object_object_get_ex(parsed_json, "d_tail", &d_tail);
  json_object_object_get_ex(parsed_json, "tcp_port", &tcp_port);
  json_object_object_get_ex(parsed_json, "pl_size", &pl_size);
  json_object_object_get_ex(parsed_json, "i_m_time", &i_m_time);
  json_object_object_get_ex(parsed_json, "udp_num", &udp_num);
  json_object_object_get_ex(parsed_json, "ttl", &ttl);
  json_object_object_get_ex(parsed_json, "p_delay", &p_delay);

  //save parsed json elements into the config_info struct
  sprintf(info->server_ip, "%s", json_object_get_string(host_ip)); 
  sprintf(info->s_port_udp, "%s", json_object_get_string(s_port));
  sprintf(info->d_port_udp, "%s", json_object_get_string(d_port));
  sprintf(info->d_port_tcp_head, "%s", json_object_get_string(d_head));
  sprintf(info->d_port_tcp_tail, "%s", json_object_get_string(d_tail));
  sprintf(info->probing_port, "%s", json_object_get_string(tcp_port));
  sprintf(info->udp_payload_sz, "%s", json_object_get_string(pl_size));
  sprintf(info->int_measu_time, "%s", json_object_get_string(i_m_time));
  sprintf(info->num_udp_packets, "%s", json_object_get_string(udp_num));
  sprintf(info->udp_ttl, "%s", json_object_get_string(ttl));
  sprintf(info->packet_delay, "%s", json_object_get_string(p_delay));
}

//calculates the checksum for the given header
unsigned short checksum(unsigned short *ptr,int nbytes){
  register long sum;
  unsigned short oddbyte;
  register short answer;

  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;
  
  return(answer);
}

int main (int argc, char **argv){

  //check for proper number of arguments
  if(argc != 2){
    printf("Usage: ./a.out config_file.json\n");
    return 0;
  }

  struct config_info* info = (struct config_info*)malloc(sizeof(struct config_info));
  char *f_name = argv[1];
  char buffer[256];

  read_config(f_name, info);  //reads and parses config file

  //Declare variables for later use
  int status, datalen, sd, *ip_flags;
  char *interface, *target, *src_ip, *dst_ip;
  struct ip iphdr;
  struct tcphdr tcphdr;
  uint8_t *data, *src_mac, *dst_mac;
  struct addrinfo hints, *res;
  struct sockaddr_in *ipv4;
  struct sockaddr_ll device;
  struct ifreq ifr;
  void *tmp;

  // Allocate memory for various arrays.
  src_mac = allocate_ustrmem (6);
  dst_mac = allocate_ustrmem (6);
  data = allocate_ustrmem (IP_MAXPACKET);
  interface = allocate_strmem (40);
  target = allocate_strmem (40);
  src_ip = allocate_strmem (INET_ADDRSTRLEN);
  dst_ip = allocate_strmem (INET_ADDRSTRLEN);
  ip_flags = allocate_intmem (4);

  low_start, low_end, high_start, high_end = 0;

  int time = atoi(info->int_measu_time);


  // Interface to send packet through.
  strcpy (interface, "ens33");

  //set up packet sniffing
  char errbuf[PCAP_ERRBUF_SIZE];    /* error buffer for pcap */

  //filtering for returning tcp packets from server with RST bit set
  char filter_exp[] = "(tcp port (5000 or 8000 or 8001)) and (tcp[tcpflags] & (tcp-rst) == (tcp-rst))";   /* filter expression [3] */
  struct bpf_program fp;      /* compiled filter program (expression) */
  bpf_u_int32 mask;     /* subnet mask */
  bpf_u_int32 net;      /* ip */
  int num_packets = 4;      /* number of packets to capture */

  /* get network number and mask associated with capture device */
  if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", interface, errbuf);
    net = 0;
    mask = 0;
  }

  /* open capture device */
  handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
    exit(EXIT_FAILURE);
  }

  /* make sure we're capturing on an Ethernet device */
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", interface);
    exit(EXIT_FAILURE);
  }

  /* compile the filter expression */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  /* apply the compiled filter */
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }

  // Submit request for a socket descriptor to look up interface.
  if ((sd = socket (AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
    perror ("first socket() failed to get socket descriptor for using ioctl() ");
    exit (EXIT_FAILURE);
  }

  // Use ioctl() to look up interface name and get its MAC address.
  memset (&ifr, 0, sizeof (ifr));
  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
    perror ("ioctl() failed to get source MAC address ");
    return (EXIT_FAILURE);
  }

  close (sd);

  // Copy source MAC address.
  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6);

  // Find interface index from interface name and store index in
  // struct sockaddr_ll device, which will be used as an argument of sendto().
  memset (&device, 0, sizeof (device));
  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
    perror ("if_nametoindex() failed to obtain interface index ");
    exit (EXIT_FAILURE);
  }

  // Set destination MAC address:
  dst_mac[0] = 0x00;
  dst_mac[1] = 0x0c;
  dst_mac[2] = 0x29;
  dst_mac[3] = 0x2e;
  dst_mac[4] = 0xee;
  dst_mac[5] = 0x26;

  // Source IPv4 address
  strcpy(src_ip, "192.168.111.158");

  // Destination IPv4 address
  strcpy(target, info->server_ip);

  // Fill out hints for getaddrinfo()
  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

  // Resolve target using getaddrinfo()
  if ((status = getaddrinfo (target, NULL, &hints, &res)) != 0) {
    fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
    exit (EXIT_FAILURE);
  }

  ipv4 = (struct sockaddr_in *) res->ai_addr;
  tmp = &(ipv4->sin_addr);
  if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
    status = errno;
    fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  freeaddrinfo (res);

  // Fill out sockaddr_ll.
  device.sll_family = AF_INET;
  device.sll_protocol = htons (ETH_P_IP);
  memcpy (device.sll_addr, dst_mac, 6);
  device.sll_halen = 6;

  // TCP data
  datalen = 5;
  data[0] = 'H';
  data[1] = 'e';
  data[2] = 'a';
  data[3] = 'd';
  data[4] = '1';


  printf("Sending test data.\n");


  //we must create a child process in order to send the UDP packets
  //while also sniffing for the returning RST packets from the server
  pid_t child = fork();

  if(child == 0) {

    //exit experiment if timeout occurs
    alarm(time + 5);
    signal(SIGALRM, alarm_handler);

    //sniff for incoming packets
    int result = pcap_loop(handle, num_packets, got_packet, NULL);

    //free necessary elements
    pcap_freecode(&fp);
    pcap_close(handle);
    

    if(result == 0){ //if expected packets are received

      //calculate time elapsed in seconds
      double total_low = (((double)low_end) - ((double)low_start)) / ((double)CLOCKS_PER_SEC);
      double low_time = total_low*1000; //convert seconds to milliseconds

      double total_high = (((double)high_end) - ((double)high_start)) / ((double)CLOCKS_PER_SEC);
      double high_time = total_high*1000; //convert seconds to milliseconds

      printf("\nLow entropy time: %f ms\nHigh entropy time: %f ms\n", low_time, high_time);
      
      double difference = total_high - total_low;
      printf("Time difference was: %2f ms\n", difference);

      //Diagnisis
      if(difference <= 100){
        printf("\nNo Network Compression detected.\n\n");
      }
      else{
        printf("\nNetwork Compression detected.\n\n");
      }
    }
    else if(result == -2){ //if timeout occurs before we get all the packets
      printf("Timeout Occurred.\n");
      printf("\nFailed to detect network compression due to insufficient information.\n\n");
    }
    else{ //if any other error occurs
      printf("Pcap error occurred.\n");
    }

    //terminate child process
    exit(0);
  }


  // create IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
  iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
  iphdr.ip_v = 4;

  // Type of service (8 bits)
  iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + TCP header + datalen
  iphdr.ip_len = (IP4_HDRLEN + TCP_HDRLEN + datalen);

  // ID sequence number (16 bits): unused, since single datagram
  iphdr.ip_id = htons (0);

  // Flags, and Fragmentation offset (3, 13 bits):
  // Zero (1 bit)
  ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
  ip_flags[1] = 0;

  // More fragments following flag (1 bit)
  ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
  ip_flags[3] = 0;

  iphdr.ip_off = htons ((ip_flags[0] << 15)
                      + (ip_flags[1] << 14)
                      + (ip_flags[2] << 13)
                      +  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
  iphdr.ip_ttl = atoi(info->udp_ttl);

  // Transport layer protocol (8 bits): 6 for TCP
  iphdr.ip_p = IPPROTO_TCP;

  // Source IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // Destination IPv4 address (32 bits)
  if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
    exit (EXIT_FAILURE);
  }

  // IPv4 header checksum, initialize to 0
  iphdr.ip_sum = 0;

  //create and populate datagram buffer
  char datagram[4096];
  memset(datagram, 0, 4096);

  memcpy(datagram, &iphdr, sizeof(struct iphdr));
  memcpy(datagram + sizeof(struct iphdr) + sizeof(struct tcphdr), data, strlen(data));

  //calculate tcp checksum for ip header
  iphdr.ip_sum = checksum((unsigned short* ) datagram, iphdr.ip_len);

  //TCP header
  //set everything in tcphdr to 0
  memset(&tcphdr, 0, sizeof(tcphdr));

  tcphdr.th_sport = htons(atoi(info->probing_port)); //set source port

  tcphdr.th_dport = htons(atoi(info->d_port_tcp_head)); //set head syn port

  tcphdr.th_seq = htonl(0); //sequence # is 0 because first packet

  tcphdr.th_ack = htonl(0); //ack # also 0 because first packet

  tcphdr.th_off = 5; //set the tcp header offset

  int* tcp_flags = allocate_intmem(6); //allocate memory for the 8 tcp flags  
  tcphdr.th_flags = 0; //set initial tchdhr flags
  tcphdr.th_flags += TH_SYN; //set the SYN flag to 1

  tcphdr.th_win = htons(5840); //set tcp window size

  tcphdr.th_sum = 0; //set checksum later

  tcphdr.th_urp = htons(0); //set urgent pointer (unused)

  //create pseudoheader and pseudogram for tcp checksum calculation
  char* pseudogram;
  struct pseudo_header psh;

  //populate pseudo ip header
  psh.source_address = inet_addr("192.168.111.158");
  psh.dest_address = ipv4->sin_addr.s_addr;
  psh.placeholder = 0;
  psh.protocol = IPPROTO_TCP;
  psh.tcp_length = htons(sizeof(struct tcphdr) + strlen(data) );

  //allocate memory for pseudogram
  int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
  pseudogram = malloc(psize);

  //copy data into pseudogram
  memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
  memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr , sizeof(struct tcphdr));
  memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data , strlen(data));
  
  //calculate tcp checksum
  tcphdr.th_sum = checksum((unsigned short*) pseudogram , psize);

  // frame length = IP header + TCP header + data
  int tcp_packet_length = IP4_HDRLEN + TCP_HDRLEN + datalen;

  int s; //socket file descriptor used for sending tcp packets

  //create socket
  if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
    perror("Failed to create tcp socket");
    exit(1);
  }

  //set socket option to include ip header
  int one = 1;
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
  {
    perror("Error setting IP_HDRINCL");
    exit(0);
  }

  //copy tcp header information into datagram
  memcpy(datagram + sizeof(struct iphdr) , &tcphdr, sizeof(struct tcphdr));

  //send datagram to server
  if (sendto (s, datagram, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
    perror("sendto failed");
  }

  close(s);


  //Create low entropy UDP train

  //converting config info parameters to numbers
  unsigned int s_port_udp = atoi(info->s_port_udp);
  unsigned int d_port_udp = atoi(info->d_port_udp);
  unsigned int udp_payload_sz = atoi(info->udp_payload_sz);;
  unsigned int num_udp_packets = atoi(info->num_udp_packets);
  unsigned int ttl = atoi(info->udp_ttl);
  unsigned int packet_delay = atoi(info->packet_delay);

  //create new sockaddr_in for udp 
  struct sockaddr_in addr, srcaddr;

  //create udp socket
  int udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0);

  if (udp_sockfd == -1) {
    perror("udp socket");
    exit(1);
  }

  //set up socket structs
  memset(&addr, 0, sizeof(addr)); //initialize memory to 0
  addr.sin_family = AF_INET; //set sin family
  inet_aton(info->server_ip, &addr.sin_addr); //set source adddress
  addr.sin_port = htons(d_port_udp); //set the destination port

  memset(&srcaddr, 0, sizeof(srcaddr)); //initialize memoryto 0
  srcaddr.sin_family = AF_INET; //set sin family
  srcaddr.sin_addr.s_addr = htonl(INADDR_ANY); //set home source address
  srcaddr.sin_port = htons(s_port_udp); //set the source port

  //set the don't fragment bit
  int value=IP_PMTUDISC_DO;
  if (setsockopt(udp_sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value))<0) {
    printf("unable to set DONT_FRAGMENT bit.\n");
    exit(1);
  }

  //set the udp ttl from config file
  if(setsockopt(udp_sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    printf("unable to set packet TTL to %u\n", ttl);
    exit(1);
  }

  //bind socket to port
  if(bind(udp_sockfd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0){
    printf("bind failed\n");
    exit(1);
  }

  //calculate size of data
  int total_data_len = num_udp_packets * (udp_payload_sz);
  
  //allocate memory for data
  uint8_t *total_data = allocate_ustrmem(total_data_len);
  
  //set the packet ids for each payload 
  uint8_t *ptr = total_data;
  for(uint16_t i = 0; i < num_udp_packets; i++){
    ptr = total_data + (i * udp_payload_sz); //ptr points to the next payload section in the buffer
    *ptr++ = (uint8_t)(i >> 8); //writes the higher order byte
    *ptr = (uint8_t)(i & 0xff); //writes the lower order byte
  }

  //send to server
  uint8_t *send_ptr = total_data;
   for(uint16_t j = 0; j < num_udp_packets; j++){

      usleep(packet_delay); //sleep for given # of microseconds to ensure enough time between sending two packets
    
      send_ptr = total_data + (j * udp_payload_sz); //send_ptr points to the next payload section in the buffer
      if((sendto(udp_sockfd, send_ptr, udp_payload_sz, MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0){
        printf("sendto failed for index: %u\n", j);
      }
   }

  close(udp_sockfd);


  //Send first tail TCP SYN packet

  //clear out old data
  memset(data, 0, IP_MAXPACKET);

  //update data to be "Tail1"
  data[0] = 'T';
  data[1] = 'a';
  data[2] = 'i';
  data[3] = 'l';
  data[4] = '1';

  struct ip iphdr_2; //create second ip packet header

  //copy data from first ip header, overwrite necessary information
  memcpy(&iphdr_2, &iphdr, sizeof(struct ip));

  // IPv4 header checksum, initialize to 0
  iphdr_2.ip_sum = 0;

  //create and populate datagram buffer
  char datagram_2[4096];
  memset(datagram_2, 0, 4096);

  memcpy(datagram_2, &iphdr_2, sizeof(struct ip));
  memcpy(datagram_2 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));

  //calculate checksum for ip header
  iphdr_2.ip_sum = checksum((unsigned short* ) datagram_2, iphdr_2.ip_len);

  //create second tcp header copied from the first one
  //overwrite relevant information
  struct tcphdr tcphdr_2;
  memcpy(&tcphdr_2, &tcphdr, sizeof(struct tcphdr));

  tcphdr_2.th_dport = htons(atoi(info->d_port_tcp_tail)); //set tail syn port

  tcphdr_2.th_seq = htonl(1); //sequence # is 1 because second packet

  tcphdr_2.th_sum = 0; //set checksum later

  //copy new data into pseudogram buffer
  memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_2 , sizeof(struct tcphdr));
  memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));
  
  //calculate tcp checksum
  tcphdr_2.th_sum = checksum((unsigned short*)pseudogram, psize);

  //create raw tcp socket
  if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
    perror("Failed to create tcp socket");
    exit(1);
  }

  //set header include (for ip header)
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
  {
    perror("Error setting IP_HDRINCL");
    exit(0);
  }

  //copy in tcp header information
  memcpy(datagram_2 + sizeof(struct ip) , &tcphdr_2, sizeof(struct tcphdr));

  //send datagram
  if (sendto (s, datagram_2, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
    perror("sendto failed");
  }

  close(s);


  //Wait for inter-measurement time between tests
  printf("\nWaiting for %d seconds between tests.\n\n", time);
  sleep(time);


  //Create third TCP SYN packet

  //clear out old data
  memset(data, 0, IP_MAXPACKET);

  //update data to be "Head2"
  data[0] = 'H';
  data[1] = 'e';
  data[2] = 'a';
  data[3] = 'd';
  data[4] = '2';

  struct ip iphdr_3; //create third tcp packet header

  memcpy(&iphdr_3, &iphdr, sizeof(struct ip)); //copy data from first ip header

  // IPv4 header checksum, initialize to 0
  iphdr_3.ip_sum = 0;

  //create and populate datagram buffer
  char datagram_3[4096];
  memset(datagram_3, 0, 4096);

  memcpy(datagram_3, &iphdr_3, sizeof(struct ip));
  memcpy(datagram_3 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));

  //calculate checksum for ip header
  iphdr_3.ip_sum = checksum((unsigned short* ) datagram_3, iphdr_3.ip_len);

  //create third tcp header copied from the first one
  struct tcphdr tcphdr_3;
  memcpy(&tcphdr_3, &tcphdr, sizeof(struct tcphdr));

  tcphdr_3.th_seq = htonl(2); //sequence # is 2 because third packet

  tcphdr_3.th_dport = htons(atoi(info->d_port_tcp_head)); //set head syn port

  tcphdr_3.th_sum = 0; //initialize checksum to 0

  //copy new data into pseudogram
  memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_3 , sizeof(struct tcphdr));
  memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));
  
  //calculate tcp checksum
  tcphdr_3.th_sum = checksum((unsigned short*)pseudogram, psize);

  //create raw tcp socket
  if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
    perror("Failed to create tcp socket");
    exit(1);
  }

  //set header include (for ip header)
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
  {
    perror("Error setting IP_HDRINCL");
    exit(0);
  }

  //copy in tcp header information
  memcpy(datagram_3 + sizeof(struct ip) , &tcphdr_3, sizeof(struct tcphdr));

  //send datagram
  if (sendto (s, datagram_3, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
    perror("sendto failed");
  }

  close(s);

  //Create high entropy data packets and send them to the server

  //generate random bits for whole stretch of data
  getrandom(total_data, total_data_len, 0);

  //write in packet id's for each stretch of payload data
  for(uint16_t i = 0; i < num_udp_packets; i++){
    ptr = total_data + (i * udp_payload_sz); //ptr points to the next payload section in the buffer
    *ptr++ = (uint8_t)(i >> 8); //writes the higher order byte
    *ptr = (uint8_t)(i & 0xff); //writes the lower order byte
  }

  //reopen previous udp socket
  if ((udp_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("udp socket");
    exit(1);
  }

  //set the don't fragment bit
  if (setsockopt(udp_sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &value, sizeof(value))<0) {
    perror("unable to set DONT_FRAGMENT bit.\n");
    exit(1);
  }

  //set the udp ttl from config file
  if(setsockopt(udp_sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    printf("unable to set packet ttl to %u\n", ttl);
    exit(1);
  }

  //bind socket to port
  if(bind(udp_sockfd, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0){
    perror("bind failed\n");
    exit(1);
  }

  //send high entropy data:
  uint8_t *send_high_ptr = total_data;
   for(uint16_t j = 0; j < num_udp_packets; j++){
           
     usleep(packet_delay); //sleep for given # of microseconds to ensure enough time between sending two packets
     
     send_high_ptr = total_data + (j * udp_payload_sz); //send_ptr points to the next payload section in the buffer
      if((sendto(udp_sockfd, send_high_ptr, udp_payload_sz, MSG_CONFIRM, (const struct sockaddr *)&addr, sizeof(addr))) < 0){
        printf("sendto failed for packet #%u\n", j);
      }
   }

  close(udp_sockfd);

  //free memory allocated for udp packets
  free(total_data);


  //Send second tail TCP SYN packet

  //clear out old data
  memset(data, 0, IP_MAXPACKET);

  //update data to be "Tail2"
  data[0] = 'T';
  data[1] = 'a';
  data[2] = 'i';
  data[3] = 'l';
  data[4] = '2';

  struct ip iphdr_4; //create fourth tcp packet header

  memcpy(&iphdr_4, &iphdr, sizeof(struct ip)); //copy data from first ip header

  // IPv4 header checksum, initialize to 0
  iphdr_4.ip_sum = 0;

  //create and populate datagram buffer
  char datagram_4[4096];
  memset(datagram_4, 0, 4096);

  memcpy(datagram_4, &iphdr_4, sizeof(struct ip));
  memcpy(datagram_4 + sizeof(struct ip) + sizeof(struct tcphdr), data, strlen(data));

  //calculate checksum for ip header
  iphdr_4.ip_sum = checksum((unsigned short* ) datagram_4, iphdr_4.ip_len);

  //create fourth tcp header copied from the first one
  struct tcphdr tcphdr_4;
  memcpy(&tcphdr_4, &tcphdr, sizeof(struct tcphdr));

  tcphdr_4.th_dport = htons(atoi(info->d_port_tcp_tail)); //set tail syn port

  tcphdr_4.th_seq = htonl(3); //sequence # is 3 because fourth packet

  tcphdr_4.th_sum = 0; //set checksum later

  //copy new data into pseudogram
  memcpy(pseudogram + sizeof(struct pseudo_header) , &tcphdr_4 , sizeof(struct tcphdr));
  memcpy(pseudogram + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, strlen(data));
  
  //calculate tcp checksum
  tcphdr_4.th_sum = checksum((unsigned short*)pseudogram, psize);

  //create raw tcp socket
  if((s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
    perror("Failed to create tcp socket");
    exit(1);
  }

  //set header include (for ip header)
  if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, &one, sizeof (one)) < 0)
  {
    perror("Error setting IP_HDRINCL");
    exit(0);
  }

  //copy in tcp header information
  memcpy(datagram_4 + sizeof(struct ip) , &tcphdr_4, sizeof(struct tcphdr));

  //send datagram
  if (sendto (s, datagram_4, tcp_packet_length , 0, (struct sockaddr *)ipv4, sizeof(struct sockaddr_in)) < 0) {
    perror("sendto failed");
  }

  close(s);

  //wait for the child process to complete before terminating the program
  wait(0);

  printf("Terminating Program.\n");


  // Free allocated memory.
  free(info);
  free(src_mac);
  free(dst_mac);
  free(data);
  free(interface);
  free(target);
  free(src_ip);
  free(dst_ip);
  free(ip_flags);
  free(pseudogram);

  return 0;
}