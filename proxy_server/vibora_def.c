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

void config_server(const char* device, conf_st* conf)
{
    memset(conf, 0, sizeof(conf_st));
    conf->local_port = LOCAL_PORT;
    conf->proxy_port = PROXY_PORT;
    conf->local_ip.s_addr = inet_addr("0.0.0.0");

    int arp_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    check_functions(arp_sock_fd, "socket");
    int status;
    struct ifreq ifr_st;
    memset(&ifr_st, 0, sizeof(struct ifreq));
    strncpy(ifr_st.ifr_name, device, strlen(device));
    status = ioctl(arp_sock_fd, SIOCGIFADDR, &ifr_st);
    check_functions(status, "ioctl");
    struct sockaddr_in* ip_addr = (struct sockaddr_in*)&ifr_st.ifr_addr;
    conf->proxy_ip.s_addr = ip_addr->sin_addr.s_addr;
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

int set_connection(conf_st* conf, const unsigned char* hash, AES_KEY* key)
{
    int tcp_sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    check_functions(tcp_sock_fd, "socket");
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    memset((void*)&server_addr, 0, addr_len);
    memset((void*)&client_addr, 0, addr_len);
    server_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(conf->proxy_port);

    int status;
    const int on = 1;
    status = setsockopt(tcp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    check_functions(status, "setsockopt");
    status = bind(tcp_sock_fd, (const struct sockaddr*)&server_addr, addr_len);
    check_functions(status, "bind");
    status = listen(tcp_sock_fd, 5);
    check_functions(status, "listen");

    int client_sock_fd = accept(tcp_sock_fd, (struct sockaddr*)&client_addr,
    &addr_len);
    check_functions(client_sock_fd, "accept");

    char recv_buffer[BUFFER_SIZE];
    char send_buffer[BUFFER_SIZE];
    memset((void*)recv_buffer, 0, BUFFER_SIZE);
    memset((void*)send_buffer, 0, BUFFER_SIZE);
    ssize_t num_of_bytes = 0;

    num_of_bytes = recv(client_sock_fd, recv_buffer, BUFFER_SIZE, 0);
    check_functions((int)num_of_bytes, "recv");
    char recv_hash[HASH_SIZE];
    memset(recv_hash, 0, HASH_SIZE);
    AES_decrypt(recv_buffer, recv_hash, key);
    const char* yes = "YES";
    const char* no = "NO";
    int flag = FALSE;
    if(strcmp(hash, recv_hash) == 0)
    {
        flag = TRUE;
        strncpy(send_buffer, yes, strlen(yes));
    }
    else strncpy(send_buffer, no, strlen(no));

    conf->local_ip.s_addr = client_addr.sin_addr.s_addr;

    num_of_bytes = send(tcp_sock_fd, send_buffer, strlen(send_buffer), 0);
    check_functions((int)num_of_bytes, "send");

    close(client_sock_fd);
    close(tcp_sock_fd);

    return flag;
}

void recv_packets(conf_st* conf, const char* device, AES_KEY* key)
{
    int udp_sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    check_functions(udp_sock_fd, "socket");
    struct sockaddr_in udp_server_addr;
    socklen_t udp_addr_len = sizeof(struct sockaddr_in);
    memset((void*)&udp_server_addr, 0, udp_addr_len);
    udp_server_addr.sin_addr.s_addr = conf->proxy_ip.s_addr;
    udp_server_addr.sin_family = AF_INET;
    udp_server_addr.sin_port = htons(conf->proxy_port);

    int status = 0;
    const int on = 1;
    status = setsockopt(udp_sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
    check_functions(status, "setsockopt");
    status = bind(udp_sock_fd, (const struct sockaddr*)&udp_server_addr,
    udp_addr_len);
    check_functions(status, "bind");

    //BPF should be here.

    int packet_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    check_functions(packet_sock_fd, "socket");
    struct sockaddr_ll packet_server_addr;
    socklen_t packet_addr_len = sizeof(struct sockaddr_ll);
    memset((void*)&packet_server_addr, 0, packet_addr_len);
    
}