// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef HM_DLL
    #if defined(_WINDOWS) || defined(_WIN32)
        #if defined (HM_IMPL)
            #define HM_API __declspec(dllexport)
        #else
            #define HM_API __declspec(dllimport)
        #endif
    #elif defined(__linux__) || defined(__FreeBSD__) || defined(__OpenBSD__)
        #if defined (HM_IMPL)
            #define HM_API __attribute__((visibility("default")))
        #else
            #define HM_API
        #endif
    #endif
#else
    #define HM_API
#endif

struct hashmap;

HM_API struct hashmap *hashmap_new(size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            uint64_t (*hash)(const void *item, 
                                             uint64_t seed0, uint64_t seed1),
                            int (*compare)(const void *a, const void *b, 
                                           void *udata),
                            void *udata);
HM_API void hashmap_free(struct hashmap *map);
HM_API void hashmap_clear(struct hashmap *map, bool update_cap);
HM_API size_t hashmap_count(struct hashmap *map);
HM_API bool hashmap_oom(struct hashmap *map);
HM_API void *hashmap_get(struct hashmap *map, void *item);
HM_API void *hashmap_set(struct hashmap *map, void *item);
HM_API void *hashmap_delete(struct hashmap *map, void *item);
HM_API void *hashmap_probe(struct hashmap *map, uint64_t position);
HM_API bool hashmap_scan(struct hashmap *map,
                  bool (*iter)(const void *item, void *udata), void *udata);
HM_API void hashmap_set_allocator(void *(*malloc)(size_t), void (*free)(void*));
HM_API uint64_t hashmap_sip(const void *data, size_t len, 
                     uint64_t seed0, uint64_t seed1);
HM_API uint64_t hashmap_murmur(const void *data, size_t len, 
                        uint64_t seed0, uint64_t seed1);

#endif
