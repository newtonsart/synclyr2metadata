/*
 * http_client.c — HTTP client implementation using libcurl
 *
 * Uses thread-local CURL handles for connection pooling and reuse.
 * Each thread gets its own handle on first use, avoiding repeated
 * init/cleanup overhead and enabling TCP/TLS connection reuse.
 */

#include "http_client.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define USER_AGENT "synclyr2metadata (https://github.com/newtonsart/synclyr2metadata)"

/* ── Thread-local CURL handle ─────────────────────────────────────────── */

static __thread CURL *tls_curl = NULL;

static const char *first_readable_file(const char *const *paths, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (paths[i] && paths[i][0] != '\0' && access(paths[i], R_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

static const char *first_readable_dir(const char *const *paths, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (paths[i] &&
            paths[i][0] != '\0' &&
            access(paths[i], R_OK | X_OK) == 0) {
            return paths[i];
        }
    }
    return NULL;
}

static const char *detect_ca_file(void)
{
    const char *const env_files[] = {
        getenv("CURL_CA_BUNDLE"),
        getenv("SSL_CERT_FILE"),
        getenv("REQUESTS_CA_BUNDLE")
    };
    const char *env_file = first_readable_file(env_files,
                                               sizeof(env_files) /
                                               sizeof(env_files[0]));
    if (env_file) {
        return env_file;
    }

    static const char *const system_files[] = {
        "/etc/ssl/cert.pem",
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/pki/tls/cacert.pem",
        "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
    };
    return first_readable_file(system_files,
                               sizeof(system_files) / sizeof(system_files[0]));
}

static const char *detect_ca_path(void)
{
    const char *const env_dirs[] = {
        getenv("SSL_CERT_DIR")
    };
    const char *env_dir = first_readable_dir(env_dirs,
                                             sizeof(env_dirs) /
                                             sizeof(env_dirs[0]));
    if (env_dir) {
        return env_dir;
    }

    static const char *const system_dirs[] = {
        "/etc/ssl/certs",
        "/etc/pki/tls/certs",
        "/etc/pki/ca-trust/extracted/pem"
    };
    return first_readable_dir(system_dirs,
                              sizeof(system_dirs) / sizeof(system_dirs[0]));
}

static int is_ca_error(CURLcode code)
{
    (void)code;
#ifdef CURLE_SSL_CACERT_BADFILE
    if (code == CURLE_SSL_CACERT_BADFILE) {
        return 1;
    }
#endif
#ifdef CURLE_PEER_FAILED_VERIFICATION
    if (code == CURLE_PEER_FAILED_VERIFICATION) {
        return 1;
    }
#endif
#ifdef CURLE_SSL_CACERT
    if (code == CURLE_SSL_CACERT) {
        return 1;
    }
#endif
    return 0;
}

static void print_ca_hint(CURLcode code, const char *ca_file,
                          const char *ca_path)
{
    if (!is_ca_error(code)) {
        return;
    }

    fprintf(stderr,
            "hint: TLS CA bundle was not found/readable in this runtime.\n");
    if (ca_file) {
        fprintf(stderr, "hint: using CA file candidate: %s\n", ca_file);
    }
    if (ca_path) {
        fprintf(stderr, "hint: using CA directory candidate: %s\n", ca_path);
    }
    fprintf(stderr,
            "hint: set CURL_CA_BUNDLE or SSL_CERT_FILE if your cert store is in a custom path.\n");
}

/*
 * Get or create the thread-local CURL handle.
 * The handle is reused across all requests within the same thread,
 * enabling HTTP keep-alive and TLS session reuse.
 */
static CURL *get_curl_handle(void)
{
    if (!tls_curl) {
        tls_curl = curl_easy_init();
    }
    return tls_curl;
}

void http_thread_cleanup(void)
{
    if (tls_curl) {
        curl_easy_cleanup(tls_curl);
        tls_curl = NULL;
    }
}

/* ── Internal helpers ─────────────────────────────────────────────────── */

/*
 * libcurl write callback. Appends received data to the response buffer.
 */
static size_t write_callback(char *data, size_t size, size_t nmemb,
                              void *userdata)
{
    size_t real_size = size * nmemb;
    HttpResponse *resp = (HttpResponse *)userdata;

    char *new_body = realloc(resp->body, resp->size + real_size + 1);
    if (!new_body) {
        return 0; /* Signal error to libcurl */
    }

    resp->body = new_body;
    memcpy(resp->body + resp->size, data, real_size);
    resp->size += real_size;
    resp->body[resp->size] = '\0';

    return real_size;
}

/* ── Public API ───────────────────────────────────────────────────────── */

int http_init(void)
{
    CURLcode res = curl_global_init(CURL_GLOBAL_DEFAULT);
    return (res == CURLE_OK) ? 0 : -1;
}

/*
 * Check if a curl error is transient and worth retrying.
 */
static int is_retryable(CURLcode code)
{
    switch (code) {
    case CURLE_COULDNT_CONNECT:
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_SEND_ERROR:
    case CURLE_RECV_ERROR:
        return 1;
    default:
        return 0;
    }
}

char *http_url_encode(const char *str)
{
    if (!str) return NULL;

    CURL *curl = get_curl_handle();
    if (!curl) return NULL;

    char *encoded = curl_easy_escape(curl, str, 0);
    char *result  = encoded ? strdup(encoded) : NULL;

    curl_free(encoded);
    return result;
}

HttpResponse *http_get(const char *url)
{
    if (!url) {
        return NULL;
    }

    static const int MAX_RETRIES    = 3;
    static const int BASE_DELAY_SEC = 1; /* 1s, 2s, 4s */

    CURL *curl = get_curl_handle();
    if (!curl) {
        return NULL;
    }
    const char *ca_file = detect_ca_file();
    const char *ca_path = detect_ca_path();

    for (int attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        HttpResponse *resp = calloc(1, sizeof(HttpResponse));
        if (!resp) {
            return NULL;
        }

        /* Configure the request (reset state from previous use) */
        curl_easy_reset(curl);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        if (ca_file) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
        }
        if (ca_path) {
            curl_easy_setopt(curl, CURLOPT_CAPATH, ca_path);
        }

        CURLcode res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
                              &resp->status_code);
            return resp;
        }

        /* Request failed */
        http_response_free(resp);

        if (attempt < MAX_RETRIES && is_retryable(res)) {
            int delay = BASE_DELAY_SEC << attempt; /* 1, 2, 4 seconds */
            fprintf(stderr, "warning: %s, retrying in %ds (%d/%d)...\n",
                    curl_easy_strerror(res), delay, attempt + 1, MAX_RETRIES);
            struct timespec ts = { .tv_sec = delay, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        } else {
            fprintf(stderr, "error: HTTP request failed: %s\n",
                    curl_easy_strerror(res));
            print_ca_hint(res, ca_file, ca_path);
            return NULL;
        }
    }

    return NULL;
}

void http_response_free(HttpResponse *resp)
{
    if (!resp) {
        return;
    }
    free(resp->body);
    free(resp);
}

void http_cleanup(void)
{
    http_thread_cleanup();
    curl_global_cleanup();
}
