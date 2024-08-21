#include "vibora.h"

void check_functions(const int status,const char* func_name)
{
    if(status == -1)
    {
        fprintf(stderr,"Error of %s calling:\t%s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void set_password(char* password_buffer)
{
    printf("Enter the password -> ");
    memset(password_buffer,0,PASSWORD_LEN);
    struct termios term_attr;
    memset(&term_attr,0,sizeof(struct termios));
    int status;
    status = tcgetattr(STDIN_FILENO,&term_attr);
    check_functions(status,"tcgetattr");
    term_attr.c_lflag &= ~ECHO;
    term_attr.c_lflag &= ~ICANON;
    status = tcsetattr(STDIN_FILENO,TCSANOW,&term_attr);
    check_functions(status,"tcsetattr");
    char c;
    u_int16_t counter = 0;
    u_int32_t i = 0;
    while(TRUE)
    {
        c = getchar();
        printf("*");
        if(c == (char)10 || counter == (PASSWORD_LEN - 1)) break;
        password_buffer[i] = c;
        counter++;
        i++;
    }
    term_attr.c_lflag |= ECHO;
    term_attr.c_lflag |= ICANON;
    status = tcsetattr(STDIN_FILENO,TCSANOW,&term_attr);
    check_functions(status,"tcsetattr");
    printf("\n");
}

void fill_struct(struct sockaddr_ll* addr, const char* device)
{
    struct ifreq ifr_st;
    memset(&ifr_st, 0, sizeof(struct ifreq));
    strcpy(ifr_st.ifr_name, device);
    int status;
    int fd=socket(AF_INET,SOCK_STREAM, 0);
    check_functions(fd, "socket");
    status = ioctl(fd, SIOCGIFINDEX, &ifr_st);
    check_functions(status, "ioctl");
    addr->sll_ifindex = ifr_st.ifr_ifindex;
    addr->sll_halen = MAC_ADDR_LEN;
    addr->sll_family = AF_PACKET;
    status = ioctl(fd, SIOCGIFHWADDR, &ifr_st);
    check_functions(status, "ioctl");
    u_char* ptr = (u_char*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        addr->sll_addr[i] = ptr[i];
    }
}

void set_aes_keys(AES_KEY* enc_key, AES_KEY* dec_key, unsigned char* hash)
{
    char user_key[PASSWORD_LEN];
    memset((void*)user_key, 0, PASSWORD_LEN);
    set_password(user_key);
    AES_set_encrypt_key((const unsigned char*)user_key, NUM_OF_BITS, enc_key);
    AES_set_decrypt_key((const unsigned char*)user_key, NUM_OF_BITS, dec_key);
    memset((void*)hash, 0, HASH_SIZE);
    MD5((const unsigned char*)user_key, strlen(user_key), hash);
}

void config_server(const char* device, conf_st* conf)
{
    memset((void*)conf, 0, sizeof(conf_st));
    conf->local_port = htons(LOCAL_PORT);
    conf->proxy_port = htons(PROXY_PORT);
    conf->proxy_port_r = htons(PROXY_PORT_R);
    conf->local_port_r = htons(LOCAL_PORT_R);
    int arp_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    check_functions(arp_sock_fd, "socket");
    int status = 0;
    struct ifreq ifr_st;
    memset((void*)&ifr_st, 0, sizeof(struct ifreq));
    strncpy(ifr_st.ifr_name, device, strlen(device));
    status = ioctl(arp_sock_fd, SIOCGIFADDR, &ifr_st);
    check_functions(status, "ioctl");
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr_st.ifr_addr;
    conf->local_ip.s_addr = addr->sin_addr.s_addr;
    status = ioctl(arp_sock_fd, SIOCGIFHWADDR, &ifr_st);
    check_functions(status, "ioctl");
    u_int8_t* ptr = (u_int8_t*)&ifr_st.ifr_hwaddr.sa_data;
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i) conf->local_mac[i] = ptr[i];
    char buffer[BUFFER_SIZE];
    ssize_t num_of_bytes = 0;
    eth_hdr* eth = NULL;
    while(TRUE)
    {
        memset((void*)buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(arp_sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom");
        eth = (eth_hdr*)buffer;
        if((eth->dest_addr[0] == conf->local_mac[0] &&
        eth->dest_addr[1] == conf->local_mac[1] &&
        eth->dest_addr[2] == conf->local_mac[2] &&
        eth->dest_addr[3] == conf->local_mac[3] &&
        eth->dest_addr[4] == conf->local_mac[4] &&
        eth->dest_addr[5] == conf->local_mac[5]) &&
        (eth->source_addr[0] != 0 &&
        eth->source_addr[1] != 0 &&
        eth->source_addr[2] != 0 &&
        eth->source_addr[3] != 0 &&
        eth->source_addr[4] != 0 &&
        eth->source_addr[5] != 0))
        {
            for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
            {
                conf->route_mac[i] = eth->source_addr[i];
            }
            break;
        }
    }
}

int set_connection(conf_st* conf, AES_KEY* enc_key, const char* hash)
{
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "socket");
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void*)&server_addr, 0, addr_len);
    server_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = conf->proxy_port;
    char send_buffer[BUFFER_SIZE];
    char recv_buffer[BUFFER_SIZE];
    memset((void*)send_buffer, 0, BUFFER_SIZE);
    memset((void*)recv_buffer, 0, BUFFER_SIZE);
    AES_encrypt(hash, send_buffer, enc_key);
    ssize_t num_of_bytes = sendto(udp_sock_fd, send_buffer, strlen(send_buffer), 0,
    (const struct sockaddr*)&server_addr, addr_len);
    check_functions((int)num_of_bytes, "sendto");
    num_of_bytes = recvfrom(udp_sock_fd, recv_buffer, BUFFER_SIZE, 0, NULL, NULL);
    check_functions((int)num_of_bytes, "recvfrom");
    int flag = FALSE;
    if((strcmp(recv_buffer, "YES")) == 0) flag = TRUE;
    close(udp_sock_fd);
    return flag;
}

void send_packet_to_proxy(conf_st* conf, AES_KEY* enc_key, const char* device)
{
    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "packet socket");
    bpf_set_port(80, packet_sock_fd);
    char recv_buffer[BUFFER_SIZE];

    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "udp socket");
    struct sockaddr_in proxy_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    proxy_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = conf->proxy_port;
    char send_buffer[BUFFER_SIZE];

    int counter = 0;
    ssize_t num_of_bytes = 0;
    size_t data_len = 0;

    while(TRUE)
    {
        if(++counter >= 5) break;
        memset((void*)recv_buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(packet_sock_fd, recv_buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom");
        printf("Rcv:\t%ld\t", num_of_bytes);
        data_len = encode_packet(recv_buffer, send_buffer, enc_key, num_of_bytes);
        printf("Enc:\t%ld\t", data_len);
        num_of_bytes = sendto(udp_sock_fd, send_buffer, data_len, 0, 
        (const struct sockaddr*)&proxy_addr, udp_addr_len);
        check_functions((int)num_of_bytes, "sendto");
        printf("Snt:\t%ld\n",num_of_bytes);
    }
}

void bpf_set_port(const u_int16_t port,const int fd)
{
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERNET_IP, 0, 9),
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 1, 0), 
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 6), 
        BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, 14),
        BPF_STMT(BPF_LD + BPF_H + BPF_IND, 14),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 2, 0),
        BPF_STMT(BPF_LD + BPF_H + BPF_IND, 16),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, port, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 1500),
        BPF_STMT(BPF_RET + BPF_K, 0)
    };

    struct sock_fprog prog = {
        .len=12,
        .filter=code
    };

    int status;
    status = setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    check_functions(status, "setsockopt");
}

size_t encode_packet(char* recv_buf, char* send_buf, AES_KEY* enc_key, ssize_t bytes)
{
    memset((void*)send_buf, 0, BUFFER_SIZE);
    unsigned int data_offset = 0;
    unsigned int num_of_blocks = bytes / 16;
    if(bytes % 16) num_of_blocks++;
    size_t data_len = num_of_blocks * 16;
    for(size_t i = 0; i < num_of_blocks; ++i)
    {
        AES_encrypt(recv_buf + data_offset, send_buf + data_offset, enc_key);
        data_offset += 16;
    }
    return data_len;
}

void print_data(const char* buffer, size_t len)
{
    eth_hdr* eth = NULL;
    size_t eth_len = sizeof(eth_hdr);
    size_t data_offset = 0;
    eth = (eth_hdr*)(buffer + data_offset);
    printf("Dst hwaddr:\t");
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        printf("%.2x", eth->dest_addr[i]);
        if((i + 1) == MAC_ADDR_LEN) printf("\n");
        else printf(":");
    }
    printf("Src hwaddr:\t");
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        printf("%.2x", eth->source_addr[i]);
        if((i + 1) == MAC_ADDR_LEN) printf("\n");
        else printf(":");
    }
    printf("Proto:\t%d\n", eth->protocol);

    data_offset += eth_len;
    ip_hdr* ip = (ip_hdr*)(buffer + data_offset);
    size_t ip_len = ip->header_length << 2;
    printf("Dst addr:\t%s\n", inet_ntoa(ip->dest_addr));
    printf("Src addr:\t%s\n", inet_ntoa(ip->source_addr));
    printf("Proto:\t%d\n",ip->protocol);
    data_offset += ip_len;
    if(ip->protocol == 6)
    {
        udp_hdr* udp = (udp_hdr*)(buffer + data_offset);
        size_t udp_len = sizeof(udp_hdr);
        printf("Dst port:\t%d\n", ntohs(udp->dest_port));
        printf("Src port:\t%d\n", ntohs(udp->source_port));
        data_offset += udp_len;
    }
    u_int8_t* ptr = (u_int8_t*)(buffer + data_offset);
    for(size_t i = data_offset; i < len; ++i)
    {
        printf("%c ", ptr[i]);
        if((i + 1) % 16 == 0 || (i + 1) == len) printf("\n");
    }
    printf("\n");
}