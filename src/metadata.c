/*
 * metadata.c — Audio file metadata reader implementation
 *
 * Uses TagLib C bindings to extract metadata from audio files
 * and provides directory scanning for batch processing.
 */

#include "metadata.h"

#include <taglib/tag_c.h>

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ── Supported extensions ──────────────────────────────────────────────── */

static const char *AUDIO_EXTENSIONS[] = {
    ".flac", ".mp3", ".ogg", ".m4a", ".opus", ".wma", ".wav", ".aac",
    NULL
};

/*
 * Check if a filename has a supported audio extension (case-insensitive).
 */
static int is_audio_file(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot) {
        return 0;
    }

    for (int i = 0; AUDIO_EXTENSIONS[i]; i++) {
        if (strcasecmp(dot, AUDIO_EXTENSIONS[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

/* ── Internal helpers ──────────────────────────────────────────────────── */

/*
 * Duplicate a string safely. Returns NULL if src is NULL or empty.
 */
static char *safe_strdup(const char *src)
{
    if (!src || src[0] == '\0') {
        return NULL;
    }
    return strdup(src);
}

/*
 * Comparison function for qsort: sort TrackMeta by track_number.
 */
static int compare_track_number(const void *a, const void *b)
{
    const TrackMeta *ta = *(const TrackMeta **)a;
    const TrackMeta *tb = *(const TrackMeta **)b;
    return ta->track_number - tb->track_number;
}

/* ── Public API ────────────────────────────────────────────────────────── */

TrackMeta *metadata_read(const char *filepath)
{
    if (!filepath) {
        return NULL;
    }

    TagLib_File *file = taglib_file_new(filepath);
    if (!file || !taglib_file_is_valid(file)) {
        if (file) {
            taglib_file_free(file);
        }
        fprintf(stderr, "warning: could not read '%s'\n", filepath);
        return NULL;
    }

    TagLib_Tag *tag = taglib_file_tag(file);
    const TagLib_AudioProperties *props = taglib_file_audioproperties(file);

    TrackMeta *meta = calloc(1, sizeof(TrackMeta));
    if (!meta) {
        taglib_file_free(file);
        return NULL;
    }

    /* Extract tag fields */
    if (tag) {
        meta->title        = safe_strdup(taglib_tag_title(tag));
        meta->artist       = safe_strdup(taglib_tag_artist(tag));
        meta->album        = safe_strdup(taglib_tag_album(tag));
        meta->track_number = (int)taglib_tag_track(tag);
    }

    /* Extract audio properties */
    if (props) {
        meta->duration = taglib_audioproperties_length(props);
    }

    char **lyrics = taglib_property_get(file, "LYRICS");
    meta->has_lyrics = (lyrics && lyrics[0] && lyrics[0][0] != '\0');
    taglib_property_free(lyrics);

    meta->filepath = strdup(filepath);

    /* Clean up TagLib allocated strings */
    taglib_tag_free_strings();
    taglib_file_free(file);

    return meta;
}

TrackMetaList *metadata_scan_dir(const char *dirpath)
{
    if (!dirpath) {
        return NULL;
    }

    DIR *dir = opendir(dirpath);
    if (!dir) {
        fprintf(stderr, "error: could not open directory '%s'\n", dirpath);
        return NULL;
    }

    /* First pass: count audio files */
    int capacity = 32;
    TrackMetaList *list = calloc(1, sizeof(TrackMetaList));
    if (!list) {
        closedir(dir);
        return NULL;
    }

    list->items = calloc((size_t)capacity, sizeof(TrackMeta *));
    if (!list->items) {
        free(list);
        closedir(dir);
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue; /* Skip hidden files and . / .. */
        }

        if (!is_audio_file(entry->d_name)) {
            continue;
        }

        /* Build full path */
        size_t path_len = strlen(dirpath) + strlen(entry->d_name) + 2;
        char *fullpath = malloc(path_len);
        if (!fullpath) {
            continue;
        }
        snprintf(fullpath, path_len, "%s/%s", dirpath, entry->d_name);

        TrackMeta *meta = metadata_read(fullpath);
        free(fullpath);

        if (!meta) {
            continue;
        }

        /* Grow array if needed */
        if (list->count >= capacity) {
            capacity *= 2;
            TrackMeta **new_items = realloc(list->items,
                                            (size_t)capacity * sizeof(TrackMeta *));
            if (!new_items) {
                metadata_free(meta);
                break;
            }
            list->items = new_items;
        }

        list->items[list->count++] = meta;
    }

    closedir(dir);

    /* Sort by track number */
    if (list->count > 1) {
        qsort(list->items, (size_t)list->count, sizeof(TrackMeta *),
              compare_track_number);
    }

    return list;
}

int metadata_sync_lyrics(const char *filepath, const char *lyrics, int force)
{
    if (!filepath || !lyrics) {
        return -1;
    }

    TagLib_File *file = taglib_file_new(filepath);
    if (!file || !taglib_file_is_valid(file)) {
        if (file) taglib_file_free(file);
        return -1;
    }

    /* Check existing lyrics if not forcing */
    if (!force) {
        char **values = taglib_property_get(file, "LYRICS");
        int has = (values && values[0] && values[0][0] != '\0');
        taglib_property_free(values);
        if (has) {
            taglib_file_free(file);
            return 0;  /* already has lyrics */
        }
    }

    /* Write lyrics */
    taglib_property_set(file, "LYRICS", lyrics);

    int result = 1;
    if (!taglib_file_save(file)) {
        fprintf(stderr, "error: failed to save '%s'\n", filepath);
        result = -1;
    }

    taglib_file_free(file);
    return result;
}

/* ── Memory management ─────────────────────────────────────────────────── */

void metadata_free(TrackMeta *meta)
{
    if (!meta) {
        return;
    }
    free(meta->title);
    free(meta->artist);
    free(meta->album);
    free(meta->filepath);
    free(meta);
}

void metadata_list_free(TrackMetaList *list)
{
    if (!list) {
        return;
    }
    for (int i = 0; i < list->count; i++) {
        metadata_free(list->items[i]);
    }
    free(list->items);
    free(list);
}
