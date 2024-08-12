#include "vibora.h"

int main(int argc, char** argv)
{
    if(argc != 2)
    {
        printf("Enter device's name.\n");
        exit(EXIT_FAILURE);
    }
    conf_st conf;
    const char* device = argv[1];
    config_server(device, &conf);
    AES_KEY aes_encrypt_key;
    AES_KEY aes_decrypt_key;
    set_aes_keys(&aes_encrypt_key, &aes_decrypt_key);
    

    pid_t pid = fork();
    if(pid) send_packet(&conf, &aes_encrypt_key);
    else recv_packet(&conf, &aes_decrypt_key, device);

    return EXIT_SUCCESS;
}