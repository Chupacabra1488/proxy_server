#include "vibora.h"

void check_functions(const int status,const char* func_name)
{
    if(status == -1)
    {
        fprintf(stderr,"Error of %s calling:\t%s\n",func_name,strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void config_server(const char* device, conf_st* conf)
{
    memset(conf, 0, sizeof(conf_st));
    conf->local_port = LOCAL_PORT;
    conf->proxy_port = PROXY_PORT;
    conf->proxy_ip.s_addr = inet_addr(PROXY_IP_ADDR);

    int arp_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    check_functions(arp_sock_fd, "socket");
    int status;
    struct ifreq ifr_st;
    memset(&ifr_st, 0, sizeof(struct ifreq));
    strncpy(ifr_st.ifr_name, device, strlen(device));
    status = ioctl(arp_sock_fd, SIOCGIFADDR, &ifr_st);
    check_functions(status, "ioctl");
    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr_st.ifr_addr;
    conf->local_ip.s_addr = ip_addr->sin_addr.s_addr;
    status = ioctl(arp_sock_fd, SIOCGIFHWADDR, &ifr_st);
    check_functions(status, "ioctl");
    u_int8_t* ptr = (u_int8_t*)(&ifr_st.ifr_hwaddr.sa_data);
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        conf->local_mac[i] = ptr[i];
    }

    char buffer[BUFFER_SIZE];
    ssize_t num_of_bytes = 0;
    eth_hdr* eth = NULL;
    while(TRUE)
    {
        memset(buffer, 0, BUFFER_SIZE);
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
                conf->router_mac[i] = eth->source_addr[i];
            }
            break;
        }
    }
}

int set_aes_keys(AES_KEY* enc_key, AES_KEY* dec_key, conf_st* conf)
{
    char user_key[PASSWORD_LEN];
    set_password(user_key);
    AES_set_encrypt_key((const char*)user_key, NUM_OF_BITS, enc_key);
    AES_set_decrypt_key((const char*)user_key, NUM_OF_BITS, dec_key);
    int exit_status = set_connection(user_key, conf, enc_key);
    return exit_status;
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

void encode_packet(char* recv_buf,char* send_buf,AES_KEY* key,ssize_t bytes)
{
    unsigned char encrypted_buffer[BUFFER_SIZE];
    memset(encrypted_buffer,0,BUFFER_SIZE);
    memset(send_buf,0,BUFFER_SIZE);
    unsigned int data_offset = 0;
    int num_of_blocks = bytes / 16;
    if(bytes % 16) num_of_blocks++;
    for(size_t i = 0; i <  num_of_blocks; ++i)
    {
        AES_encrypt((unsigned char*)recv_buf + data_offset,
        encrypted_buffer + data_offset, key);
        data_offset += 16;
    }
    size_t len = strlen((const char*)encrypted_buffer);
    memcpy(send_buf, encrypted_buffer, len);
}

void send_packet(const conf_st* conf, AES_KEY* key)
{
    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "socket");  
    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);
    ssize_t num_of_bytes;

    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "socket");
    struct sockaddr_in proxy_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    memset(&proxy_addr, 0, udp_addr_len);
    proxy_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(conf->proxy_port);
    char send_buffer[BUFFER_SIZE];

    while(TRUE)
    {
        num_of_bytes = recvfrom(packet_sock_fd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom");
        printf("Recv: %ld\t",num_of_bytes);
        encode_packet(buffer, send_buffer, key, num_of_bytes);
        printf("Encr: %ld\t",strlen(send_buffer));
        num_of_bytes = sendto(udp_sock_fd, send_buffer, strlen(send_buffer), 0,
        (struct sockaddr*)&proxy_addr, udp_addr_len);
        check_functions((int)num_of_bytes, "sendto");
        printf("Sent: %ld\n",num_of_bytes);
    }

    close(packet_sock_fd);
    close(udp_sock_fd);
}

void decode_packet(char* enc_buf,char* dec_buf,ssize_t bytes,AES_KEY* key)
{
    unsigned char decrypted_buffer[BUFFER_SIZE];
    memset(decrypted_buffer,0,BUFFER_SIZE);
    memset(dec_buf,0,BUFFER_SIZE);
    unsigned int data_offset = 0;
    int num_of_blocks = bytes / 16;
    if(bytes % 16) num_of_blocks++;
    for(size_t i = 0; i < num_of_blocks; ++i)
    {
        AES_decrypt((unsigned char*)enc_buf + data_offset,
        decrypted_buffer + data_offset, key);
        data_offset += 16;
    }
    size_t len = data_offset;
    memcpy(dec_buf, decrypted_buffer, len);
}

void recv_packet(const conf_st* conf, AES_KEY* key, const char* device)
{
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "socket");
    struct sockaddr_in local_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    memset(&local_addr, 0, udp_addr_len);
    local_addr.sin_addr.s_addr = conf->local_ip.s_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(conf->local_port);
    int status = bind(udp_sock_fd, (const struct sockaddr*)&local_addr, udp_addr_len);
    check_functions(status, "bind");
    const int on = 1;
    status = setsockopt(udp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    check_functions(status, "setsockopt");
    char recv_buffer[BUFFER_SIZE];

    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "socket");
    char send_buffer[BUFFER_SIZE];
    struct sockaddr_ll hw_addr;
    socklen_t hw_addr_len = sizeof(struct sockaddr_ll);
    fill_struct(&hw_addr, device);

    eth_hdr eth;
    size_t eth_len = sizeof(eth_hdr);
    ssize_t num_of_bytes = 0;
    eth.protocol = htons(ETHERNET_IP);
    for(size_t i = 0; i < MAC_ADDR_LEN; ++i)
    {
        eth.dest_addr[i] = conf->local_mac[i];
        eth.source_addr[i] = conf->router_mac[i];
    }

    while(TRUE)
    {
        memset(recv_buffer, 0, BUFFER_SIZE);
        memset(send_buffer, 0, BUFFER_SIZE);
        num_of_bytes = recvfrom(udp_sock_fd, recv_buffer, BUFFER_SIZE, 0,
        NULL, NULL);
        check_functions((int)num_of_bytes, "recvfrom recv");

        AES_decrypt(recv_buffer, send_buffer, key);
        memcpy(send_buffer, (void*)&eth, eth_len);

        num_of_bytes = sendto(packet_sock_fd, send_buffer, strlen(send_buffer), 0,
        (struct sockaddr*)&hw_addr, hw_addr_len);
        check_functions((int)num_of_bytes, "sendto");
    }
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

int set_connection(const char* user_key, conf_st* conf, AES_KEY* key)
{
    unsigned char hash[HASH_SIZE];
    memset((void*)hash, 0, HASH_SIZE);
    MD5((const unsigned char*)user_key, strlen(user_key), hash);
    unsigned char message[HASH_SIZE];
    memset((void*)message, 0, HASH_SIZE);
    AES_encrypt(hash, message, key);

    int tcp_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    check_functions(tcp_sock_fd, "socket");
    struct sockaddr_in server_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void*)&server_addr, 0, addr_len);
    ssize_t num_of_bytes = 0;
    server_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(conf->proxy_port);
    int status = 0;
    char buffer[BUFFER_SIZE];
    memset((void*)buffer, 0, BUFFER_SIZE);

    status = connect(tcp_sock_fd, (const struct sockaddr*)&server_addr, addr_len);
    check_functions(status, "connect");
    num_of_bytes = send(tcp_sock_fd, message, strlen(message), 0);
    check_functions((int)num_of_bytes, "send");
    num_of_bytes = recv(tcp_sock_fd, buffer, BUFFER_SIZE, 0);
    check_functions((int)num_of_bytes, "recv");
    if((strcmp(buffer, "YES")) == 0) return EXIT_SUCCESS;
    else return EXIT_FAILURE;
}

void print_welcome(const conf_st* conf)
{
    printf("[*] Established connection with %s:%d\n", inet_ntoa(conf->proxy_ip), conf->proxy_port);
    printf("==== WELCOME ====\n");
}