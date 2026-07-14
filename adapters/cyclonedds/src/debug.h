/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * debug.h - Debug utilities and logging interface
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#ifndef PQ_DEBUG_H
#define PQ_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Check if logging is enabled at compile time
#ifndef PQ_LOGGING_ENABLED
#define PQ_LOGGING_ENABLED 1
#endif

// Compile-time default level
#ifndef PQ_DEFAULT_LOG_LEVEL
#define PQ_DEFAULT_LOG_LEVEL 3 // INFO
#endif

// Simple debug levels
typedef enum {
    PQ_LOG_NONE = 0,  // No logging
    PQ_LOG_ERROR = 1, // Errors only
    PQ_LOG_WARN = 2,  // Warnings + errors
    PQ_LOG_INFO = 3,  // Information + above
    PQ_LOG_TRACE = 4, // Trace/debug + above
    PQ_LOG_DATA = 5   // Data dumps + above
} pq_log_level_t;

// Global debug level
extern pq_log_level_t g_pq_log_level;

// Initialize debug system
void pq_debug_init(void);

// Internal logging function
void pq_log_internal(pq_log_level_t level, const char *func, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

// Main logging macros - only compile if logging enabled
#if PQ_LOGGING_ENABLED

#define DBG_ERR(fmt, ...)                                                                          \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_ERROR)                                                        \
            pq_log_internal(PQ_LOG_ERROR, __func__, fmt, ##__VA_ARGS__);                           \
    } while (0)
#define DBG_WARN(fmt, ...)                                                                         \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_WARN)                                                         \
            pq_log_internal(PQ_LOG_WARN, __func__, fmt, ##__VA_ARGS__);                            \
    } while (0)
#define DBG_INFO(fmt, ...)                                                                         \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_INFO)                                                         \
            pq_log_internal(PQ_LOG_INFO, __func__, fmt, ##__VA_ARGS__);                            \
    } while (0)
#define DBG_TRACE(fmt, ...)                                                                        \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_TRACE)                                                        \
            pq_log_internal(PQ_LOG_TRACE, __func__, fmt, ##__VA_ARGS__);                           \
    } while (0)
#define DBG_DATA(fmt, ...)                                                                         \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_DATA)                                                         \
            pq_log_internal(PQ_LOG_DATA, __func__, fmt, ##__VA_ARGS__);                            \
    } while (0)

// Specialized crypto debugging
#define DBG_CRYPTO(fmt, ...) DBG_TRACE("CRYPTO: " fmt, ##__VA_ARGS__)
#define DBG_KEM(fmt, ...) DBG_TRACE("KEM: " fmt, ##__VA_ARGS__)
#define DBG_SIG(fmt, ...) DBG_TRACE("SIG: " fmt, ##__VA_ARGS__)
#define DBG_HANDSHAKE(fmt, ...) DBG_INFO("HANDSHAKE: " fmt, ##__VA_ARGS__)

// Data dumping
#define DBG_DUMP_HEX(data, len, desc)                                                              \
    do {                                                                                           \
        if (g_pq_log_level >= PQ_LOG_DATA) {                                                       \
            pq_dump_hex(data, len, desc);                                                          \
        }                                                                                          \
    } while (0)

#else
// When logging is disabled, all macros become no-ops
#define DBG_ERR(fmt, ...)                                                                          \
    do {                                                                                           \
    } while (0)
#define DBG_WARN(fmt, ...)                                                                         \
    do {                                                                                           \
    } while (0)
#define DBG_INFO(fmt, ...)                                                                         \
    do {                                                                                           \
    } while (0)
#define DBG_TRACE(fmt, ...)                                                                        \
    do {                                                                                           \
    } while (0)
#define DBG_DATA(fmt, ...)                                                                         \
    do {                                                                                           \
    } while (0)
#define DBG_CRYPTO(fmt, ...)                                                                       \
    do {                                                                                           \
    } while (0)
#define DBG_KEM(fmt, ...)                                                                          \
    do {                                                                                           \
    } while (0)
#define DBG_SIG(fmt, ...)                                                                          \
    do {                                                                                           \
    } while (0)
#define DBG_HANDSHAKE(fmt, ...)                                                                    \
    do {                                                                                           \
    } while (0)
#define DBG_DUMP_HEX(data, len, desc)                                                              \
    do {                                                                                           \
    } while (0)
#endif

// Utility functions (only declared if logging enabled)
#if PQ_LOGGING_ENABLED
void pq_dump_hex(const unsigned char *data, size_t len, const char *description);
const char *pq_log_level_str(pq_log_level_t level);
#endif

#endif // PQ_DEBUG_H