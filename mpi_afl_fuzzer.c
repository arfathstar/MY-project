// mpi_afl_fuzzer.c
// Compile with: mpicc -o mpi_afl_fuzzer mpi_afl_fuzzer.c
// Run with: mpirun -np 3 ./mpi_afl_fuzzer

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define MAX_INPUT_SIZE 4096
#define BITMAP_SIZE 65536

void write_to_file(const char* filename, const char* data, int len) {
    FILE* f = fopen(filename, "wb");
    if (!f) {
        perror("fopen");
        exit(1);
    }
    fwrite(data, 1, len, f);
    fclose(f);
}

bool is_new_coverage(const char* map_file, uint8_t* bitmap) {
    FILE* f = fopen(map_file, "rb");
    if (!f) return false;

    uint8_t buf[BITMAP_SIZE];
    fread(buf, 1, sizeof(buf), f);
    fclose(f);

    bool new_coverage = false;
    for (int i = 0; i < BITMAP_SIZE; i++) {
        if (buf[i] && !bitmap[i]) {
            bitmap[i] = buf[i];
            new_coverage = true;
        }
    }
    return new_coverage;
}

void mutate_input(char* input, int* len) {
    if (*len <= 1) return;
    int pos = rand() % (*len - 1);
    input[pos] ^= 0xFF; // simple mutation: flip bits
}

int main(int argc, char** argv) {
    int rank, size;
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    char input[MAX_INPUT_SIZE] = "hello world";
    int input_len = strlen(input) + 1;
    uint8_t bitmap[BITMAP_SIZE] = {0};

    char* input_file = "input.txt";
    char* map_file = "/tmp/afl_map.out";

    srand((unsigned)time(NULL) + rank);

    while (1) {
        if (rank == 0) {
            mutate_input(input, &input_len);
            write_to_file(input_file, input, input_len);

            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "cat %s | afl-showmap -o %s -m none -t 1000 -- ./test_target",
                     input_file, map_file);
            system(cmd);

            if (is_new_coverage(map_file, bitmap)) {
                MPI_Bcast(&input_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
                MPI_Bcast(input, input_len, MPI_CHAR, 0, MPI_COMM_WORLD);
                printf("[Rank 0] New input shared: %s\n", input);
            }
        } else {
            MPI_Bcast(&input_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
            MPI_Bcast(input, input_len, MPI_CHAR, 0, MPI_COMM_WORLD);

            write_to_file(input_file, input, input_len);

            char cmd[512];
            snprintf(cmd, sizeof(cmd),
                     "cat %s | afl-showmap -o /dev/null -m none -t 1000 -- ./test_target",
                     input_file);
            system(cmd);

            printf("[Rank %d] Processed input: %s\n", rank, input);
        }
        sleep(1);
    }

    MPI_Finalize();
    return 0;
}

