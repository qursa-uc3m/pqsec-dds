/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * bench_hook.h - Benchmarking and performance measurement interface
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#ifndef MEASURE_HANDSHAKE_TIME_H
#define MEASURE_HANDSHAKE_TIME_H

#ifdef MEASURE_HANDSHAKE_TIME
#include <time.h>
#endif

void shm_write(struct timespec start);
void shm_read(struct timespec *start);
void shm_finalize(void);

#endif // MEASURE_HANDSHAKE_TIME_H
