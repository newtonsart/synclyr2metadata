/*
 * lrclib.c — LRCLIB API client implementation
 *
 * Builds API URLs, performs HTTP requests, and parses JSON responses
 * into LrclibTrack structs.
 */

#include "lrclib.h"
#include "http_client.h"
#include "cJSON.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LRCLIB_BASE_URL "https://lrclib.net/api"
#define URL_BUFFER_SIZE 1024

static LrclibTrack *parse_track(const cJSON *obj);

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Get the string value of a cJSON field, or NULL if missing/wrong type.
 */
static const char *json_get_string(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsString(item) ? item->valuestring : NULL;
}

static double json_get_number(const cJSON *obj, const char *key)
{
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    return cJSON_IsNumber(item) ? item->valuedouble : 0.0;
}

static char *normalized_copy(const char *src)
{
    if (!src) {
        return NULL;
    }

    size_t len = strlen(src);
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (isalnum(c)) {
            out[j++] = (char)tolower(c);
        }
    }
    out[j] = '\0';

    return out;
}

static int normalized_match_score(const char *expected, const char *actual,
                                  int exact_score, int contains_score)
{
    char *a = normalized_copy(expected);
    char *b = normalized_copy(actual);
    int score = 0;

    if (a && b && a[0] != '\0' && b[0] != '\0') {
        if (strcmp(a, b) == 0) {
            score = exact_score;
        } else if (strstr(a, b) || strstr(b, a)) {
            score = contains_score;
        }
    }

    free(a);
    free(b);
    return score;
}

static int candidate_score(const LrclibTrack *candidate,
                           const char *artist, const char *track,
                           const char *album, double duration,
                           int prefer_synced)
{
    int score = 0;
    int track_score = normalized_match_score(track, candidate->track_name, 60, 25);
    int artist_score = normalized_match_score(artist, candidate->artist_name, 40, 15);

    if (track_score == 0 || artist_score == 0) {
        return 0;
    }

    score += track_score;
    score += artist_score;

    if (album && candidate->album_name) {
        score += normalized_match_score(album, candidate->album_name, 15, 5);
    }

    if (duration > 0.0 && candidate->duration > 0.0) {
        double diff = duration - candidate->duration;
        if (diff < 0.0) {
            diff = -diff;
        }
        if (diff <= 2.0) {
            score += 15;
        } else if (diff <= 5.0) {
            score += 8;
        }
    }

    if (candidate->instrumental) {
        score += 20;
    } else if (candidate->synced_lyrics && candidate->synced_lyrics[0] != '\0') {
        score += prefer_synced ? 30 : 15;
    } else if (candidate->plain_lyrics && candidate->plain_lyrics[0] != '\0') {
        score += 5;
    }

    return score;
}

static LrclibTrack *pick_best_from_search_json(cJSON *json,
                                                const char *artist,
                                                const char *track,
                                                const char *album,
                                                double duration,
                                                int prefer_synced)
{
    if (!cJSON_IsArray(json)) {
        return NULL;
    }

    LrclibTrack *best = NULL;
    int best_score = 0;
    int count = cJSON_GetArraySize(json);

    for (int i = 0; i < count; i++) {
        LrclibTrack *candidate = parse_track(cJSON_GetArrayItem(json, i));
        if (!candidate) {
            continue;
        }

        int score = candidate_score(candidate, artist, track, album, duration,
                                    prefer_synced);
        if (score >= 70 && score > best_score) {
            lrclib_track_free(best);
            best = candidate;
            best_score = score;
        } else {
            lrclib_track_free(candidate);
        }
    }

    return best;
}

/*
 * Parse a JSON object into a heap-allocated LrclibTrack.
 * Extracts lyrics plus enough identity fields for search scoring.
 */
static LrclibTrack *parse_track(const cJSON *obj)
{
    if (!cJSON_IsObject(obj)) {
        return NULL;
    }

    const char *synced = json_get_string(obj, "syncedLyrics");
    const char *plain  = json_get_string(obj, "plainLyrics");
    const char *artist = json_get_string(obj, "artistName");
    const char *title  = json_get_string(obj, "trackName");
    const char *album  = json_get_string(obj, "albumName");
    cJSON *inst_item   = cJSON_GetObjectItemCaseSensitive(obj, "instrumental");

    LrclibTrack *track = calloc(1, sizeof(LrclibTrack));
    if (!track) {
        return NULL;
    }

    track->artist_name   = artist ? strdup(artist) : NULL;
    track->track_name    = title  ? strdup(title)  : NULL;
    track->album_name    = album  ? strdup(album)  : NULL;
    track->duration      = json_get_number(obj, "duration");
    track->synced_lyrics = synced ? strdup(synced) : NULL;
    track->plain_lyrics  = plain  ? strdup(plain)  : NULL;
    track->instrumental  = cJSON_IsTrue(inst_item) ? 1 : 0;

    return track;
}


/*
 * Perform a GET request and parse the response as JSON.
 * Returns a cJSON object on success, NULL on failure.
 * Caller must free the result with cJSON_Delete().
 */
static __thread int lookup_failed;

void lrclib_lookup_reset(void) { lookup_failed = 0; }
int lrclib_lookup_failed(void) { return lookup_failed; }

static cJSON *api_request(const char *url)
{
    if (lookup_failed) return NULL;
    HttpResponse *resp = http_get(url);
    if (!resp) {
        lookup_failed = 1;
        return NULL;
    }

    if (resp->status_code != 200) {
        if (resp->status_code == 404) {
            /* Not found is a valid "no result", not an error */
        } else {
            lookup_failed = 1;
            /* The HTTP client already logs the global 429 cooldown. */
            if (resp->status_code != 429)
                fprintf(stderr, "error: LRCLIB API returned HTTP %ld\n",
                        resp->status_code);
        }
        http_response_free(resp);
        return NULL;
    }

    cJSON *json = cJSON_Parse(resp->body);
    http_response_free(resp);

    if (!json) {
        lookup_failed = 1;
        fprintf(stderr, "error: failed to parse API response as JSON\n");
    }

    return json;
}

/* ── Public API ────────────────────────────────────────────────────────── */

LrclibTrack *lrclib_get(const char *artist, const char *track,
                         const char *album, double duration)
{
    if (!artist || !track) {
        fprintf(stderr, "error: artist and track are required\n");
        return NULL;
    }

    char *enc_artist = http_url_encode(artist);
    char *enc_track  = http_url_encode(track);
    if (!enc_artist || !enc_track) {
        free(enc_artist);
        free(enc_track);
        return NULL;
    }

    char url[URL_BUFFER_SIZE];
    int len = snprintf(url, sizeof(url),
                       "%s/get?artist_name=%s&track_name=%s",
                       LRCLIB_BASE_URL, enc_artist, enc_track);

    /* Append optional parameters */
    if (album) {
        char *enc_album = http_url_encode(album);
        if (enc_album) {
            snprintf(url + len, sizeof(url) - (size_t)len,
                     "&album_name=%s", enc_album);
            free(enc_album);
        }
    }

    if (duration > 0.0) {
        size_t current_len = strlen(url);
        snprintf(url + current_len, sizeof(url) - current_len,
                 "&duration=%.0f", duration);
    }

    free(enc_artist);
    free(enc_track);

    cJSON *json = api_request(url);
    if (!json) {
        return NULL;
    }

    LrclibTrack *result = parse_track(json);
    cJSON_Delete(json);

    return result;
}

LrclibTrack *lrclib_search_best(const char *artist, const char *track,
                                 const char *album, double duration,
                                 int prefer_synced)
{
    if (!artist || !track) {
        fprintf(stderr, "error: artist and track are required\n");
        return NULL;
    }

    char *enc_artist = http_url_encode(artist);
    char *enc_track  = http_url_encode(track);
    if (!enc_artist || !enc_track) {
        free(enc_artist);
        free(enc_track);
        return NULL;
    }

    char url[URL_BUFFER_SIZE];
    int len = snprintf(url, sizeof(url),
                       "%s/search?artist_name=%s&track_name=%s",
                       LRCLIB_BASE_URL, enc_artist, enc_track);
    (void)len;

    free(enc_artist);
    free(enc_track);

    cJSON *json = api_request(url);
    if (json) {
        LrclibTrack *best = pick_best_from_search_json(json, artist, track,
                                                       album, duration,
                                                       prefer_synced);
        cJSON_Delete(json);
        if (best) {
            return best;
        }
    }

    char query[URL_BUFFER_SIZE];
    snprintf(query, sizeof(query), "%s %s", artist, track);

    char *enc_query = http_url_encode(query);
    if (!enc_query) {
        return NULL;
    }

    snprintf(url, sizeof(url), "%s/search?q=%s", LRCLIB_BASE_URL, enc_query);
    free(enc_query);

    json = api_request(url);
    if (!json) {
        return NULL;
    }

    LrclibTrack *best = pick_best_from_search_json(json, artist, track, album,
                                                   duration, prefer_synced);
    cJSON_Delete(json);
    return best;
}

/* ── Memory management ─────────────────────────────────────────────────── */

void lrclib_track_free(LrclibTrack *track)
{
    if (!track) {
        return;
    }
    free(track->artist_name);
    free(track->track_name);
    free(track->album_name);
    free(track->synced_lyrics);
    free(track->plain_lyrics);
    free(track);
}
