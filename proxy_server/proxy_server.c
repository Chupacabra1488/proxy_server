#include "vibora.h"

int main(int argc, char** argv)
{
    AES_KEY aes_encrypt_key;
    AES_KEY aes_decrypt_key;
    unsigned char hash[HASH_SIZE];
    set_aes_keys(&aes_encrypt_key, &aes_decrypt_key, hash);
    conf_st conf;
    if(argc != 2)
    {
        printf("Enter device's name.\n");
        exit(EXIT_FAILURE);
    }
    char* device = argv[1];
    config_server(device, &conf);
    int status = 0;
    while(TRUE)
    {
        status = set_connection(&conf, hash, &aes_decrypt_key);
        if(status == TRUE) break;
    }

    return EXIT_SUCCESS;
}