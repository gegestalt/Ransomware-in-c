#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

#define KEY_LEN 32

void decrypt_file(const char* path, const unsigned char* key_bytes);

int main(int argc, char* argv[]) {
    // Load the key from the key file
    unsigned char key_bytes[KEY_LEN];
    FILE* key_file = fopen("key.bin", "rb");
    fread(key_bytes, 1, KEY_LEN, key_file);
    fclose(key_file);

    // Find and decrypt all .enc files in the current directory
    DIR* dir;
    struct dirent* ent;
    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG) {
                char path[PATH_MAX];
                sprintf(path, "./%s", ent->d_name);
                char* enc_extension = strstr(ent->d_name, ".enc");
                if (enc_extension != NULL && strlen(enc_extension) == 4) {
                    printf("Decrypting file: %s\n", path);
                    decrypt_file(path, key_bytes);
                    // Rename the decrypted file to remove the .enc extension
                    char* extension = strrchr(ent->d_name, '.');
                    if (extension != NULL) {
                        *extension = '\0';
                        rename(path, ent->d_name);
                    }
                }
            }
        }
        closedir(dir);
    } else {
        perror("Could not open directory");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void decrypt_file(const char* path, const unsigned char* key_bytes) {
    FILE* in_file = fopen(path, "rb");
    fseek(in_file, 0, SEEK_END);
    long ciphertext_len = ftell(in_file) - KEY_LEN;
    rewind(in_file);

    unsigned char iv[KEY_LEN];
    fread(iv, 1, KEY_LEN, in_file);

    unsigned char ciphertext[ciphertext_len];
    fread(ciphertext, 1, ciphertext_len, in_file);
    fclose(in_file);

    unsigned char plaintext[ciphertext_len];
    for (int i = 0; i < ciphertext_len; i++) {
        plaintext[i] = ciphertext[i] ^ key_bytes[i % KEY_LEN] ^ iv[i % KEY_LEN];
    }

    FILE* out_file = fopen(path, "wb");
    fwrite(plaintext, 1, ciphertext_len, out_file);
    fclose(out_file);
}
