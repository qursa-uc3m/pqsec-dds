/*
 * Copyright (C) 2023-2025 Javier Blanco-Romero @fj-blanco (UC3M)
 *
 * PQSec-DDS: Post-Quantum Cryptography DDS Security Plugin
 * debug.c - Debug utilities and logging functions
 *
 * This authentication plugin implements Post-Quantum Cryptography algorithms
 * for DDS security via liboqs and OpenSSL oqs-provider. Based on CycloneDDS
 * built-in authentication plugin and DDS Security specification v1.1.
 */

#include "debug.h"
#include <stdarg.h>
#include <time.h>
#include <unistd.h>

// Global debug configuration
pq_log_level_t g_pq_log_level = PQ_DEFAULT_LOG_LEVEL;

#if PQ_LOGGING_ENABLED

static int g_pq_log_colors = 1; // Auto-detect terminal

// Level names
static const char *const PQ_LEVEL_NAMES[] = {
    [PQ_LOG_NONE] = "NONE", [PQ_LOG_ERROR] = "ERROR", [PQ_LOG_WARN] = "WARN",
    [PQ_LOG_INFO] = "INFO", [PQ_LOG_TRACE] = "TRACE", [PQ_LOG_DATA] = "DATA"};

// Simple colors
static const char *const PQ_COLORS[] = {
    [PQ_LOG_NONE] = "",
    [PQ_LOG_ERROR] = "\033[31m", // Red
    [PQ_LOG_WARN] = "\033[33m",  // Yellow
    [PQ_LOG_INFO] = "\033[32m",  // Green
    [PQ_LOG_TRACE] = "\033[34m", // Blue
    [PQ_LOG_DATA] = "\033[35m"   // Magenta
};

void pq_debug_init(void) {
    // Check environment variable for runtime level override
    const char *env_level = getenv("PQ_DEBUG_LEVEL");
    if (env_level) {
        // Try numeric first
        int level = atoi(env_level);
        if (level >= PQ_LOG_NONE && level <= PQ_LOG_DATA) {
            g_pq_log_level = (pq_log_level_t)level;
        } else {
            // Try string-based levels
            for (int i = 0; i <= PQ_LOG_DATA; i++) {
                if (strcasecmp(env_level, PQ_LEVEL_NAMES[i]) == 0) {
                    g_pq_log_level = (pq_log_level_t)i;
                    break;
                }
            }
        }
    }

    // Auto-detect color support
    g_pq_log_colors = isatty(STDERR_FILENO);

    // Allow color override
    const char *env_colors = getenv("PQ_DEBUG_COLORS");
    if (env_colors) {
        g_pq_log_colors = (strcasecmp(env_colors, "off") != 0 && strcasecmp(env_colors, "0") != 0);
    }

    DBG_INFO("PQ-DDS debug initialized (level: %s)\n", PQ_LEVEL_NAMES[g_pq_log_level]);
}

static void get_timestamp(char *buffer, size_t size) {
    struct timespec ts;
    struct tm *tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);

    snprintf(buffer, size, "%02d:%02d:%02d.%03ld", tm_info->tm_hour, tm_info->tm_min,
             tm_info->tm_sec, ts.tv_nsec / 1000000);
}

void pq_log_internal(pq_log_level_t level, const char *func, const char *fmt, ...) {
    if (level > g_pq_log_level)
        return;

    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));

    const char *color = g_pq_log_colors ? PQ_COLORS[level] : "";
    const char *reset = g_pq_log_colors ? "\033[0m" : "";
    const char *level_name = PQ_LEVEL_NAMES[level];

    // Format: [timestamp] LEVEL PQ-DDS func(): message
    fprintf(stderr, "[%s] %s%-5s%s PQ-DDS %s(): ", timestamp, color, level_name, reset, func);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fflush(stderr);
}

void pq_dump_hex(const unsigned char *data, size_t len, const char *description) {
    if (!data || len == 0) {
        DBG_DATA("%s: (null or empty)\n", description);
        return;
    }

    DBG_DATA("%s (%zu bytes):\n", description, len);

    for (size_t i = 0; i < len; i++) {
        if (i % 16 == 0) {
            fprintf(stderr, "  %04zx: ", i);
        }
        fprintf(stderr, "%02x ", data[i]);

        if (i % 16 == 15 || i == len - 1) {
            // Pad to align ASCII
            for (size_t j = i + 1; j % 16 != 0; j++) {
                fprintf(stderr, "   ");
            }

            // Print ASCII
            fprintf(stderr, " |");
            size_t start = (i / 16) * 16;
            for (size_t j = start; j <= i; j++) {
                char c = (data[j] >= 32 && data[j] <= 126) ? data[j] : '.';
                fprintf(stderr, "%c", c);
            }
            fprintf(stderr, "|\n");
        }
    }

    fflush(stderr);
}

const char *pq_log_level_str(pq_log_level_t level) {
    if (level >= PQ_LOG_NONE && level <= PQ_LOG_DATA) {
        return PQ_LEVEL_NAMES[level];
    }
    return "UNKNOWN";
}

#else
// Stub implementations when logging is disabled
void pq_debug_init(void) {}
void pq_log_internal(pq_log_level_t level, const char *func, const char *fmt, ...) {}
void pq_dump_hex(const unsigned char *data, size_t len, const char *description) {}
const char *pq_log_level_str(pq_log_level_t level) { return "DISABLED"; }
#endif