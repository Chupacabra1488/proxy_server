#include "vibora.h"

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        printf("Enter device's name.\n");
        exit(EXIT_FAILURE);
    }
    conf_st conf;
    char* device = argv[1];
    config_server(&conf, device);
    AES_KEY aes_encrypt_key;
    AES_KEY aes_decrypt_key;
    char hash[HASH_SIZE];
    set_aes_keys(&aes_encrypt_key, &aes_decrypt_key, hash);
    
    int connection_status = 0;
    while(TRUE)
    {
        connection_status = set_connection(&conf, &aes_decrypt_key, hash);
        if(connection_status)
        {
            printf("==== ==== ACCESS ALLOWED ==== ====\n");
            printf("[*] Established connection with:\t%s:%d\n",inet_ntoa(conf.local_ip),
            ntohs(conf.local_port));
            break;
        }
    }

    pid_t pid = fork();
    if(pid) recv_packet_from_local(&conf, &aes_decrypt_key, device);
    else send_packet_to_local(&conf, &aes_encrypt_key, device);

    return EXIT_SUCCESS;
}