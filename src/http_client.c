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
#include <errno.h>

#define USER_AGENT "synclyr2metadata/9b9a9ef-local (https://github.com/newtonsart/synclyr2metadata)"
#define AUTH_FILE "/etc/synclyr2metadata/credentials"
#define API_ORIGIN "https://lrclib.net/api/"

/* ── Thread-local CURL handle ─────────────────────────────────────────── */

static __thread CURL *tls_curl = NULL;

/* One shared request budget for all workers; use monotonic time. */
static pthread_mutex_t request_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec next_request;
static int rate_limited;
static struct curl_slist *auth_headers;
static int has_api_key;

static int append_header(const char *name, const char *value)
{
    if (!value || !*value) return 0;
    if (strpbrk(value, "\r\n")) return -1;
    char line[512];
    int n = snprintf(line, sizeof(line), "%s: %s", name, value);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    struct curl_slist *next = curl_slist_append(auth_headers, line);
    if (!next) return -1;
    auth_headers = next;
    return 0;
}

static int load_auth(void)
{
    char app[256] = "", key[256] = "", line[512];
    FILE *f = fopen(AUTH_FILE, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (!strncmp(line, "LRCLIB_APP_ID=", 14)) {
                if (strlen(line + 14) >= sizeof(app)) { fclose(f); return -1; }
                strcpy(app, line + 14);
            } else if (!strncmp(line, "LRCLIB_API_KEY=", 15)) {
                if (strlen(line + 15) >= sizeof(key)) { fclose(f); return -1; }
                strcpy(key, line + 15);
            }
        }
        fclose(f);
    } else if (errno != ENOENT) {
        fprintf(stderr, "error: cannot read LRCLIB credentials file\n");
        return -1;
    }
    const char *a = getenv("LRCLIB_APP_ID");
    const char *k = getenv("LRCLIB_API_KEY");
    if (!a) a = app;
    if (!k) k = key;
    if (append_header("Lrclib-App-Id", a) || append_header("Lrclib-Api-Key", k)) {
        curl_slist_free_all(auth_headers);
        auth_headers = NULL;
        return -1;
    }
    has_api_key = *k != 0;
    if (has_api_key) fprintf(stderr, "LRCLIB: authenticated mode (250ms delay)\n");
    return 0;
}

static void wait_until(struct timespec deadline)
{
    while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL) == EINTR) {}
}

static void delay_requests(long seconds, long nanoseconds)
{
    clock_gettime(CLOCK_MONOTONIC, &next_request);
    next_request.tv_sec += seconds;
    next_request.tv_nsec += nanoseconds;
    if (next_request.tv_nsec >= 1000000000L) {
        next_request.tv_sec++;
        next_request.tv_nsec -= 1000000000L;
    }
}

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
    if (res != CURLE_OK) return -1;
    if (load_auth() != 0) {
        curl_global_cleanup();
        return -1;
    }
    return 0;
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
        /* Restrict authentication to the intended HTTPS API; never redirect secrets. */
        int authenticated = auth_headers && !strncmp(url, API_ORIGIN, sizeof(API_ORIGIN)-1);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, authenticated ? 0L : 1L);
        if (authenticated) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, auth_headers);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
        if (ca_file) {
            curl_easy_setopt(curl, CURLOPT_CAINFO, ca_file);
        }
        if (ca_path) {
            curl_easy_setopt(curl, CURLOPT_CAPATH, ca_path);
        }

        pthread_mutex_lock(&request_lock);
        if (rate_limited) {
            pthread_mutex_unlock(&request_lock);
            resp->status_code = 429;
            return resp;
        }

        wait_until(next_request);
        CURLcode res = curl_easy_perform(curl);
        if (authenticated && has_api_key) delay_requests(0, 250000000L);
        else delay_requests(1, 0);

        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE,
                              &resp->status_code);
            if (resp->status_code == 429) {
                curl_off_t retry_after = 0;
                curl_easy_getinfo(curl, CURLINFO_RETRY_AFTER, &retry_after);
                long delay = 5L << attempt;
                if (retry_after > 60 || attempt == MAX_RETRIES) {
                    rate_limited = 1;
                    fprintf(stderr, "warning: LRCLIB rate limited; deferring remaining requests in this run\n");
                    pthread_mutex_unlock(&request_lock);
                    return resp;
                }
                if (retry_after > delay) delay = (long)retry_after;
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                long jitter = now.tv_nsec % 500000000L;
                delay_requests(delay, jitter);
                fprintf(stderr, "warning: HTTP 429; global cooldown %lds (%d/%d)\n",
                        delay, attempt + 1, MAX_RETRIES);
                /* Hold the request lock during the retry loop's wait so
                 * other workers cannot make requests during cooldown. */
                wait_until(next_request);
                pthread_mutex_unlock(&request_lock);
                http_response_free(resp);
                continue;
            }
            pthread_mutex_unlock(&request_lock);
            return resp;
        }
        pthread_mutex_unlock(&request_lock);

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
    curl_slist_free_all(auth_headers);
    auth_headers = NULL;
    has_api_key = 0;
    curl_global_cleanup();
}
