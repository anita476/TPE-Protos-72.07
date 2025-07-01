#include "../include/metrics.h"
#include "../include/logger.h"
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

void metrics_increment_errors(void) {
    metrics.errors++;
}

server_metrics* metrics_get(void) {
    return &metrics;
}

void metrics_cleanup(void) {
    time_t uptime = time(NULL) - metrics.start_time;
    log(INFO, "[METRICS] Server shutdown - Final statistics:");
    log(INFO, "[METRICS] Total connections: %llu", metrics.total_connections);
    log(INFO, "[METRICS] Max concurrent: %u", metrics.max_concurrent_connections);
    log(INFO, "[METRICS] Bytes received: %llu", metrics.bytes_transferred_in);
    log(INFO, "[METRICS] Bytes sent: %llu", metrics.bytes_transferred_out);
    log(INFO, "[METRICS] Total bytes transferred: %llu", metrics.total_bytes_transferred);
    log(INFO, "[METRICS] Metrics system cleaned up");
    log(INFO, "[METRICS] Error count: %u", metrics.errors);
    log(INFO, "[METRICS] Server uptime: %ld seconds", uptime);
}