/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * bench_hook.c - Benchmarking and performance measurement hooks
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#include "bench_hook.h"

#ifdef MEASURE_HANDSHAKE_TIME

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define SHARED_MEMORY_NAME "/measure_handshake_time_shm"
#define SHARED_MEMORY_SIZE sizeof(struct timespec)

void shm_write(struct timespec start) {
    int shm_fd = shm_open(SHARED_MEMORY_NAME, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }
    if (ftruncate(shm_fd, SHARED_MEMORY_SIZE) == -1) {
        perror("ftruncate");
        exit(EXIT_FAILURE);
    }

    struct timespec *m =
        mmap(NULL, SHARED_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (m == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    *m = start;
    munmap(m, SHARED_MEMORY_SIZE);
    close(shm_fd);
}

void shm_read(struct timespec *start) {
    int shm_fd = shm_open(SHARED_MEMORY_NAME, O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        exit(EXIT_FAILURE);
    }

    struct timespec *m =
        mmap(NULL, SHARED_MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (m == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    *start = *m;
    munmap(m, SHARED_MEMORY_SIZE);
    close(shm_fd);
}

void shm_finalize(void) {
    if (shm_unlink(SHARED_MEMORY_NAME) == -1)
        perror("shm_unlink");
    else
        printf("Shared memory deleted\n");
}

#endif // MEASURE_HANDSHAKE_TIME
