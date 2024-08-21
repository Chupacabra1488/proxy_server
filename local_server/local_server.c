#include "vibora.h"

int main(int argc, char** argv)
{
    if(argc != 3)
    {
        printf("Usage: <./local_server> <device name> <proxy IP>\n");
        exit(EXIT_FAILURE);
    }
    conf_st conf;
    const char* device = argv[1];
    config_server(device, &conf);
    conf.proxy_ip.s_addr = inet_addr(argv[2]);
    AES_KEY aes_encrypt_key;
    AES_KEY aes_decrypt_key;
    char hash[HASH_SIZE];
    set_aes_keys(&aes_encrypt_key, &aes_decrypt_key, hash);
    
    int connection_status = set_connection(&conf, &aes_encrypt_key, hash);
    if(connection_status == FALSE) return EXIT_FAILURE;
    else
    {
        printf("==== ==== ACCESS ALLOWED ==== ====.\n");
        printf("Server is listening on:\t%s:%d\n",inet_ntoa(conf.proxy_ip),ntohs(conf.proxy_port));
    }

    send_packet_to_proxy(&conf, &aes_encrypt_key, device);

    pid_t pid = fork();
    if(pid) send_packet_to_proxy(&conf, &aes_encrypt_key, device);
    else recv_packet_from_proxy(&conf, &aes_decrypt_key, device);

    return EXIT_SUCCESS;
}
