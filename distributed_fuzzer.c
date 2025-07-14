// distributed_fuzzer.c
#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <fcntl.h>

#define MAX_INPUT_SIZE 1024 * 1024  // 1MB
#define TAG_INPUT 0
#define TAG_CRASH 1

char *QUEUE_DIR;
char *CRASH_DIR;

#define MAX_HASHES 100000
char known_hashes[MAX_HASHES][SHA_DIGEST_LENGTH];
int known_hash_count = 0;

int hash_known(unsigned char *digest) {
    for (int i = 0; i < known_hash_count; i++) {
        if (memcmp(known_hashes[i], digest, SHA_DIGEST_LENGTH) == 0) {
            return 1;
        }
    }
    return 0;
}

void add_hash(unsigned char *digest) {
    if (known_hash_count < MAX_HASHES) {
        memcpy(known_hashes[known_hash_count++], digest, SHA_DIGEST_LENGTH);
    }
}
void compute_sha1(const unsigned char *data, size_t len, unsigned char *out_hash) {
    SHA1(data, len, out_hash);  // one-shot API, works in OpenSSL 1.1 and 3.0+
}

void inject_input(unsigned char *data, size_t len, int is_crash) {
    char path[512];
    snprintf(path, sizeof(path), "%s/mpi_injected_%ld", QUEUE_DIR, time(NULL));
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        printf("Injected %s input to %s\n", is_crash ? "CRASH" : "NORMAL", path);
    }
}

void process_dir(const char *dir_path, int tag, int my_rank, int size, MPI_Comm comm) {
    static char known_files[100000][256];
    static int known_file_count = 0;
void compute_sha1(const unsigned char *data, size_t len, unsigned char *out_hash) {
    SHA1(data, len, out_hash);  // one-shot API, works in OpenSSL 1.1 and 3.0+
}

    DIR *d = opendir(dir_path);
    if (!d) return;

    struct dirent *entry;
    while ((entry = readdir(d))) {
        if (entry->d_type != DT_REG) continue;
        if (strncmp(entry->d_name, "id:", 3) != 0 && tag == TAG_INPUT) continue;

        int known = 0;
        for (int i = 0; i < known_file_count; i++) {
            if (strcmp(known_files[i], entry->d_name) == 0) {
                known = 1;
                break;
            }
        }
        if (known) continue;

        snprintf(known_files[known_file_count++], 256, "%s", entry->d_name);

        char fpath[512];
        snprintf(fpath, sizeof(fpath), "%s/%s", dir_path, entry->d_name);
        FILE *f = fopen(fpath, "rb");
        if (!f) continue;

        unsigned char *buf = malloc(MAX_INPUT_SIZE);
        size_t len = fread(buf, 1, MAX_INPUT_SIZE, f);
        fclose(f);

        unsigned char digest[SHA_DIGEST_LENGTH];
        compute_sha1(buf, len, digest);

        if (hash_known(digest)) {
            free(buf);
            continue;
        }
        add_hash(digest);

        // Send to all other nodes
        for (int node = 0; node < size; node++) {
            if (node == my_rank) continue;
            MPI_Send(&len, 1, MPI_UNSIGNED_LONG, node, tag, comm);
            MPI_Send(buf, len, MPI_BYTE, node, tag, comm);
            printf("Sent %s input (%zu bytes) to node %d\n", tag == TAG_CRASH ? "CRASH" : "INPUT", len, node);
        }

        free(buf);
    }

    closedir(d);
}

void receive_inputs(int my_rank, int size, MPI_Comm comm) {
    MPI_Status status;
    int flag;
    MPI_Iprobe(MPI_ANY_SOURCE, MPI_ANY_TAG, comm, &flag, &status);

    if (flag) {
        size_t len;
        MPI_Recv(&len, 1, MPI_UNSIGNED_LONG, status.MPI_SOURCE, status.MPI_TAG, comm, &status);

        unsigned char *buf = malloc(len);
        MPI_Recv(buf, len, MPI_BYTE, status.MPI_SOURCE, status.MPI_TAG, comm, &status);

        unsigned char digest[SHA_DIGEST_LENGTH];
        compute_sha1(buf, len, digest);

        if (!hash_known(digest)) {
            add_hash(digest);
            inject_input(buf, len, status.MPI_TAG == TAG_CRASH);
        } else {
            printf("Discarded duplicate input from node %d\n", status.MPI_SOURCE);
        }

        free(buf);
    }
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);

    int my_rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &my_rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    printf("Node %d/%d starting distributed fuzzer\n", my_rank, size);

    char queue_dir_path[256], crash_dir_path[256];
    snprintf(queue_dir_path, sizeof(queue_dir_path), "./output_dir/fuzzer%d/queue", my_rank);
    snprintf(crash_dir_path, sizeof(crash_dir_path), "./output_dir/fuzzer%d/crashes", my_rank);
    QUEUE_DIR = queue_dir_path;
    CRASH_DIR = crash_dir_path;

    while (1) {
        process_dir(QUEUE_DIR, TAG_INPUT, my_rank, size, MPI_COMM_WORLD);
        process_dir(CRASH_DIR, TAG_CRASH, my_rank, size, MPI_COMM_WORLD);
        receive_inputs(my_rank, size, MPI_COMM_WORLD);
        usleep(500000);  // 0.5s delay
    }

    MPI_Finalize();
    return 0;
}
