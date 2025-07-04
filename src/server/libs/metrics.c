#include "../include/metrics.h"
#include "../include/logger.h"
#include <inttypes.h>           // To ensure the uint64_t format is correct in every OS  
#include <string.h>
#include <stdlib.h>
#include <time.h>

static server_metrics metrics = {0};

void metrics_init(void) {
    memset(&metrics, 0, sizeof(metrics));
    metrics.start_time = time(NULL);
    log(INFO, "[METRICS_INIT] Metrics initialized");
}

void metrics_increment_connections(void) {
    metrics.total_connections++;
    metrics.concurrent_connections++;
    if (metrics.concurrent_connections > metrics.max_concurrent_connections) {  
        metrics.max_concurrent_connections = metrics.concurrent_connections;
    }
}

void metrics_decrement_connections(void) {
    if (metrics.concurrent_connections > 0) {
        metrics.concurrent_connections--;
    }
}

void metrics_add_bytes_in(uint64_t bytes) {
    metrics.bytes_transferred_in += bytes;
    metrics.total_bytes_transferred += bytes;
}

void metrics_add_bytes_out(uint64_t bytes) {
    metrics.bytes_transferred_out += bytes;
    metrics.total_bytes_transferred += bytes;
}

void metrics_increment_errors(error_type_t error_type) {
    metrics.error_counts[error_type]++;
    metrics.total_errors++;
}

server_metrics* metrics_get(void) {
    return &metrics;
}

void metrics_cleanup(void) {
    time_t uptime = time(NULL) - metrics.start_time;
    log(INFO, "[METRICS] Server shutdown - Final statistics:");
    log(INFO, "[METRICS] Total connections: %" PRIu64, metrics.total_connections);
    log(INFO, "[METRICS] Max concurrent: %u", metrics.max_concurrent_connections);
    log(INFO, "[METRICS] Bytes received: %" PRIu64, metrics.bytes_transferred_in);
    log(INFO, "[METRICS] Bytes sent: %" PRIu64, metrics.bytes_transferred_out);
    log(INFO, "[METRICS] Total bytes transferred: %" PRIu64, metrics.total_bytes_transferred);
    log(INFO, "[METRICS] Total errors: %u", metrics.total_errors);
    log(INFO, "[METRICS] Network errors: %u", metrics.error_counts[ERROR_TYPE_NETWORK]);
    log(INFO, "[METRICS] Protocol errors: %u", metrics.error_counts[ERROR_TYPE_PROTOCOL]);
    log(INFO, "[METRICS] Auth errors: %u", metrics.error_counts[ERROR_TYPE_AUTH]);
    log(INFO, "[METRICS] System errors: %u", metrics.error_counts[ERROR_TYPE_SYSTEM]);
    log(INFO, "[METRICS] Timeout errors: %u", metrics.error_counts[ERROR_TYPE_TIMEOUT]);
    log(INFO, "[METRICS] Other errors: %u", metrics.error_counts[ERROR_TYPE_OTHER]);
    log(INFO, "[METRICS] Server uptime: %ld seconds", uptime);
    log(INFO, "[METRICS] Metrics system cleaned up");
}