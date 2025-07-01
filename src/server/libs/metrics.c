#include "include/metrics.h"
#include "include/logger.h"
#include <string.h>
#include <stdlib.h>

static server_metrics metrics = {0};

void metrics_init(void) {
    memset(&metrics, 0, sizeof(metrics));
    log(INFO, "[METRICS_INIT] Metrics initialized");
}

void metrics_increment_connection(void) {
    metrics.total_connections++;
    metrics.concurrent_connections++;
    if (metrics.concurrent_connections > metrics.max_concurrent_connections) {  
        metrics.max_concurrent_connections = metrics.concurrent_connections;
    }
}

void metrics_decrement_connection(void) {
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

server_metrics* metrics_get(void) {
    return &metrics;
}

void metrics_cleanup(void) {
    log(INFO, "[METRICS] Server shutdown - Final statistics:");
    log(INFO, "[METRICS] Total connections: %lu", metrics.total_connections);
    log(INFO, "[METRICS] Max concurrent: %u", metrics.max_concurrent_connections);
    log(INFO, "[METRICS] Total bytes transferred: %lu", metrics.total_bytes_transferred);
    log(INFO, "[METRICS] Metrics system cleaned up");
}