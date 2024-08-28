#include "vibora.h"

void check_functions(const int status,const char* func_name)
{
    if(status == -1)
    {
        fprintf(stderr,"Error of %s calling:\t%s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
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

void config_server(conf_st* conf, const char* device)
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
    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr_st.ifr_addr;
    conf->proxy_ip.s_addr = ip_addr->sin_addr.s_addr;
    status = ioctl(arp_sock_fd, SIOCGIFHWADDR, &ifr_st);
    check_functions(status, "ioctl");
    u_int8_t* ptr = (u_int8_t*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i) conf->proxy_mac[i] = ptr[i];
    char buffer[BUFFER_SIZE];
    ssize_t num_of_bytes = 0;
    eth_hdr* eth = NULL;
    while(TRUE)
    {
        memset((void*)buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(arp_sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom");
        eth = (eth_hdr*)buffer;
        if((eth->dest_addr[0] == conf->proxy_mac[0] &&
        eth->dest_addr[1] == conf->proxy_mac[1] &&
        eth->dest_addr[2] == conf->proxy_mac[2] &&
        eth->dest_addr[3] == conf->proxy_mac[3] &&
        eth->dest_addr[4] == conf->proxy_mac[4] &&
        eth->dest_addr[5] == conf->proxy_mac[5]) &&
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

int set_connection(conf_st* conf, AES_KEY* dec_key, const char* hash)
{
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "socket");
    struct sockaddr_in proxy_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void*)&proxy_addr, 0, addr_len);
    proxy_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = conf->proxy_port;
    const int on = 1;
    int status = setsockopt(udp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    check_functions(status, "setsockopt");
    status = bind(udp_sock_fd, (const struct sockaddr*)&proxy_addr, addr_len);
    check_functions(status, "bind");
    char recv_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    memset((void*)recv_buffer, 0, BUFFER_SIZE);
    memset((void*)send_buffer, 0, BUFFER_SIZE);
    ssize_t num_of_bytes = 0;
    struct sockaddr_in client_addr;
    memset((void*)&client_addr, 0, addr_len);
    num_of_bytes = recvfrom(udp_sock_fd, recv_buffer, BUFFER_SIZE, 0,
    (struct sockaddr*)&client_addr, &addr_len);
    check_functions((int)num_of_bytes, "recvfrom");
    char recv_hash[HASH_SIZE];
    memset((void*)recv_hash, 0, HASH_SIZE);
    AES_decrypt(recv_buffer, recv_hash, dec_key);
    int flag = FALSE;
    const char* yes = "YES";
    const char* no = "NO";
    if((strcmp(hash, recv_hash)) == 0)
    {
        conf->local_ip.s_addr = client_addr.sin_addr.s_addr;
        flag = TRUE;
        strncpy(send_buffer, yes, strlen(yes));
    }
    else
    {
        flag = FALSE;
        strncpy(send_buffer, no, strlen(no));
    }
    num_of_bytes = sendto(udp_sock_fd, send_buffer, strlen(send_buffer), 0,
    (const struct sockaddr*)&client_addr, addr_len);
    check_functions((int)num_of_bytes, "sendto");
    close(udp_sock_fd);
    return flag;
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

size_t decode_packet(char* enc_buf, char* dec_buf, ssize_t bytes, AES_KEY* dec_key)
{
    memset((void*)dec_buf, 0, BUFFER_SIZE);
    unsigned int data_offset = 0;
    unsigned int num_of_blocks = bytes / 16;
    if(bytes % 16) num_of_blocks++;

    for(size_t i = 0; i < num_of_blocks; ++i)
    {
        AES_decrypt(enc_buf + data_offset, dec_buf + data_offset, dec_key);
        data_offset += 16;
    }
    size_t data_len = num_of_blocks * 16;
    return data_len;
}

void recv_packet_from_local(conf_st* conf, AES_KEY* dec_key, const char* device)
{
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "udp socket");
    struct sockaddr_in proxy_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    memset((void*)&proxy_addr, 0, udp_addr_len);
    proxy_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = conf->proxy_port;
    char recv_buffer[BUFFER_SIZE];
    int status = 0;
    const int on = 1;
    status = setsockopt(udp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    check_functions(status, "setsockopt");
    status = bind(udp_sock_fd, (const struct sockaddr*)&proxy_addr, udp_addr_len);
    check_functions(status, "bind");

    char send_buffer[BUFFER_SIZE];
    ssize_t num_of_bytes = 0;
    unsigned int counter = 0;
    size_t data_len = 0;

    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "packet socket");
    struct sockaddr_ll packet_addr;
    socklen_t pack_addr_len = sizeof(struct sockaddr_ll);
    fill_struct(&packet_addr, device);


    while(TRUE)
    {
        memset((void*)recv_buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(udp_sock_fd, recv_buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions(status, "recvfrom");
        printf("Rcv:\t%ld\t", num_of_bytes);
        data_len = decode_packet(recv_buffer, send_buffer, num_of_bytes, dec_key);
        printf("Dec:\t%ld\n", data_len);
        print_data(send_buffer, data_len);
        printf("\n***********************************************************\n\n");
        change_addrs(send_buffer, conf);
        print_data(send_buffer, data_len);
        num_of_bytes = sendto(packet_sock_fd, send_buffer, data_len, 0,
        (const struct sockaddr*)&packet_addr, pack_addr_len);
        check_functions((int)num_of_bytes, "sendto");
    }
    close(udp_sock_fd);
    close(packet_sock_fd);
}

void change_addrs(char* buffer, conf_st* conf)
{
    eth_hdr* eth = (eth_hdr*)buffer;
    size_t eth_len = sizeof(eth_hdr);
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        eth->dest_addr[i] = conf->route_mac[i];
        eth->source_addr[i] = conf->proxy_mac[i];
    }
    ip_hdr* ip = (ip_hdr*)(buffer + eth_len);
    ip->source_addr.s_addr = conf->proxy_ip.s_addr;
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

void send_packet_to_local(conf_st* conf, AES_KEY* enc_key, const char* device)
{
    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "packet socket");
    char recv_buffer[BUFFER_SIZE];

    //BPF is here

    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "udp socket");
    struct sockaddr_in local_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    memset((void*)&local_addr, 0, udp_addr_len);
    local_addr.sin_addr.s_addr = conf->local_ip.s_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = conf->local_port_r;
    char send_buffer[BUFFER_SIZE];

    ssize_t num_of_bytes = 0;
    size_t data_len = 0;
    while(TRUE)
    {
        memset((void*)recv_buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(packet_sock_fd, recv_buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom");
        data_len = encode_packet(recv_buffer, send_buffer, enc_key, num_of_bytes);
        num_of_bytes = sendto(udp_sock_fd, send_buffer, data_len, 0,
        (const struct sockaddr*)&local_addr, udp_addr_len);
        check_functions((int)num_of_bytes, "sendto");
    }
    close(packet_sock_fd);
    close(udp_sock_fd);
}

void bpf_set_addrs(conf_st* conf, const int sock_fd)
{
    u_int32_t local_addr = ntohl(conf->local_ip.s_addr);
    u_int32_t proxy_addr = ntohl(conf->proxy_ip.s_addr);

    struct sock_filter code[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
        BPF_JUMP(BPF_JMP + BPF_JEQ +BPF_K, ETHERNET_IP, 0, 7),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 26),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, local_addr, 3, 0),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 30),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, proxy_addr, 0, 1),
        BPF_STMT(BPF_RET +BPF_K, 1500),
        BPF_STMT(BPF_RET + BPF_K, 0)
    };

    struct sock_fprog prog = {
        .len = 8,
        .filter = code
    };

    int status = 0;
    status = setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog));
    check_functions(status, "setsockopt");
}