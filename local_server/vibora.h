#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <linux/filter.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <termios.h>

#define TRUE 1
#define FALSE 0
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define CONFIG_FILE "server.conf"
#define BUFFER_SIZE 1500
#define PASSWORD_LEN 256
#define NUM_OF_BITS 128
#define ETHERNET_IP 0x0800
#define ETHERNET_ARP 0x0806
#define ETHERNET_RARP 0x8035
#define ETHERNET_IPV6 0x86dd
#define DEVICE_LEN 64
#define LOCAL_PORT 7501
#define PROXY_PORT 7500
#define LOCAL_PORT_R 7502
#define PROXY_PORT_R 7503
#define HASH_SIZE 128

struct ethernet_header
{
    u_int8_t dest_addr[MAC_ADDR_LEN];
    u_int8_t source_addr[MAC_ADDR_LEN];
    u_int16_t protocol;
};

struct ip_header
{
    unsigned char header_length:4,
                  version:4;
    u_int8_t type_of_service;
    u_int16_t total_length;
    u_int16_t identification;
    u_int16_t frag_off;
    u_int8_t time_to_live;
    u_int8_t protocol;
    u_int16_t check_sum;
    struct in_addr source_addr;
    struct in_addr dest_addr;
};

struct icmp_header
{
    u_int8_t type_of_message;
    u_int8_t code_of_message;
    u_int16_t check_sum;
    u_int16_t identification;
    u_int16_t sequence;
};

struct pseudo_header
{
    struct in_addr source_addr;
    struct in_addr dest_addr;
    u_int8_t zero_field;
    u_int8_t protocol;
    u_int16_t total_length;
};

struct udp_header
{
    u_int16_t source_port;
    u_int16_t dest_port;
    u_int16_t length;
    u_int16_t check_sum;
};

struct tcp_header
{
    u_int16_t source_port;
    u_int16_t dest_port;
    u_int32_t seq_number;
    u_int32_t ack_number;
    u_int16_t data_offset:4,
              reserved:4,
              cwr:1,
              ece:1,
              urg:1,
              ack:1,
              psh:1,
              rst:1,
              syn:1,
              fin:1;
    u_int16_t window_size;
    u_int16_t check_sum;
    u_int16_t urg_ptr;
};

struct arp_header
{
    u_int16_t hw_type;
    u_int16_t protocol_type;
    u_int8_t hw_addr_len;
    u_int8_t proto_addr_len;
    u_int16_t op_code;
    u_int8_t sender_hwaddr[MAC_ADDR_LEN];
    u_int8_t sender_ipaddr[IP_ADDR_LEN];
    u_int8_t target_hwaddr[MAC_ADDR_LEN];
    u_int8_t target_ipaddr[IP_ADDR_LEN];
};

struct config_data
{
    struct in_addr local_ip;
    struct in_addr proxy_ip;
    u_int16_t local_port;
    u_int16_t proxy_port;
    u_int16_t local_port_r;
    u_int16_t proxy_port_r;
    u_int8_t local_mac[MAC_ADDR_LEN];
    u_int8_t route_mac[MAC_ADDR_LEN];
};

typedef struct ethernet_header eth_hdr;
typedef struct ip_header ip_hdr;
typedef struct icmp_header icmp_hdr;
typedef struct pseudo_header ps_hdr;
typedef struct udp_header udp_hdr;
typedef struct tcp_header tcp_hdr;
typedef struct arp_header arp_hdr;
typedef struct config_data conf_st;

void config_server(const char* device, conf_st* conf);
void check_functions(const int status,const char* func_name);
void set_password(char* password_buffer);
void fill_struct(struct sockaddr_ll* addr, const char* device);
void set_aes_keys(AES_KEY* enc_key, AES_KEY* dec_key, unsigned char* hash);
int set_connection(conf_st* conf, AES_KEY* enc_key, const char* hash);
void send_packet_to_proxy(conf_st* conf, AES_KEY* enc_key, const char* device);
size_t encode_packet(char* recv_buf, char* send_buf, AES_KEY* enc_key, ssize_t bytes);
void bpf_set_port(const u_int16_t port,const int fd);
void print_data(const char* buffer, size_t len);