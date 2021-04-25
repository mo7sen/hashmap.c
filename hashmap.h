// Copyright 2020 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

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

typedef uint64_t (*hm_hash_fn)(const void *item, uint64_t seed0, uint64_t seed1);
typedef int (*hm_cmp_fn)(const void *a, const void *b, void *udata);

HM_API struct hashmap *hashmap_new(size_t elsize, size_t cap, 
                            uint64_t seed0, uint64_t seed1,
                            hm_hash_fn hash, hm_cmp_fn compare,
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

#define HM_CONCAT_IMPL(a,b) a##b
#define HM_CONCAT(a,b) HM_CONCAT_IMPL(a,b)

#define HashFunction(K) HM_CONCAT(HashFunction_,K)
#define CmpFunction(K) HM_CONCAT(CmpFunction_,K)

#define HashFunctionDefineCustom(K, pVar) \
  static uint64_t                         \
  HashFunction(K)(                        \
      const K* pVar,                      \
      uint64_t seed0,                     \
      uint64_t seed1)

#define HashFunctionDefine(K)        \
  HashFunctionDefineCustom(K, pItem) \
  {                                  \
    return hashmap_murmur(           \
        pItem,                       \
        sizeof(K),                   \
        seed0,                       \
        seed1);                      \
  }

#define CmpFunctionDefineCustom(K, pVar0, pVar1) \
  static int                                     \
  CmpFunction(K)(                               \
      const K* pVar0,                             \
      const K* pVar1,                             \
      void *udata)

#define CmpFunctionDefine(K)                 \
  CmpFunctionDefineCustom(K, pItem0, pItem1) \
  {                                          \
    return memcmp(pItem0, pItem1, sizeof(K));\
  }

#define Map(K, V) struct hashmap *
#define HashmapEntry(K, V) struct { K key; V value; }

#define Hashmap(K, V)     HM_CONCAT(HM_CONCAT(HashmapStruct_, K), HM_CONCAT(_, V))
#define HashmapNew(K, V)  HM_CONCAT(HM_CONCAT(HashmapNew_, K), HM_CONCAT(_, V))
#define HashmapPush(K, V) HM_CONCAT(HM_CONCAT(HashmapPush_, K), HM_CONCAT(_, V))
#define HashmapGet(K, V)  HM_CONCAT(HM_CONCAT(HashmapGet_, K), HM_CONCAT(_, V))
#define HashmapSize(K, V) HM_CONCAT(HM_CONCAT(HashmapSize_, K), HM_CONCAT(_, V))
#define HashmapFree(K, V) HM_CONCAT(HM_CONCAT(HashmapFree_, K), HM_CONCAT(_, V))
#define HashmapRemove(K, V) HM_CONCAT(HM_CONCAT(HashmapRemove_, K), HM_CONCAT(_, V))
#define HashmapClear(K, V) HM_CONCAT(HM_CONCAT(HashmapClear_, K), HM_CONCAT(_, V))
#define HashmapIter(K, V) HM_CONCAT(HM_CONCAT(HashmapIter_, K), HM_CONCAT(_, V))
#define HashmapIterImpl(K, V) HM_CONCAT(HM_CONCAT(HashmapIterImpl_, K), HM_CONCAT(_, V))

#define HashmapNewDefine(K, V)        \
  static Map(K, V) HashmapNew(K, V)() \
  {                                   \
    return hashmap_new(               \
        sizeof(K) + sizeof(V),        \
        0, 0, 0,                      \
        (hm_hash_fn)HashFunction(K),  \
        (hm_cmp_fn)CmpFunction(K),    \
        NULL);                        \
  }

#define HashmapPushDefine(K, V)                              \
  static void HashmapPush(K, V)(Map(K, V) map, K key, V val) \
  {                                                          \
    HashmapEntry(K, V) entry = {key, val};                   \
    hashmap_set(map, &entry);                                \
  }

#define HashmapGetDefine(K, V)                          \
  static V* HashmapGet(K, V)(Map(K, V) map, K key)      \
  {                                                     \
    HashmapEntry(K, V) entry = {.key = key};            \
    HashmapEntry(K, V) *res = hashmap_get(map, &entry); \
    if(res) {                                           \
      return &(res->value);                             \
    }                                                   \
    return NULL;                                        \
  }

#define HashmapRemoveDefine(K, V)                       \
  static void HashmapRemove(K, V)(Map(K, V) map, K key) \
  {                                                     \
    HashmapEntry(K, V) entry = {.key = key};            \
    hashmap_delete(map, &entry);                        \
  }

#define HashmapSizeDefine(K, V)                  \
  static size_t HashmapSize(K, V)(Map(K, V) map) \
  {                                              \
    return hashmap_count(map);                   \
  }

#define HashmapFreeDefine(K, V)                \
  static void HashmapFree(K, V)(Map(K, V) map) \
  {                                            \
    hashmap_free(map);                         \
  }

#define HashmapClearDefine(K, V)                \
  static void HashmapClear(K, V)(Map(K, V) map) \
  {                                             \
    hashmap_clear(map, false);                  \
  }

#define HashmapIterImplDefine(K, V)                                  \
  static bool HashmapIterImpl(K, V)(const void *data, void* iter_fn) \
  {                                                                  \
    const HashmapEntry(K, V) *entry = data;                          \
    ((void(*)(K,V))iter_fn)(entry->key, entry->value);               \
    return true;                                                     \
  }

#define HashmapIterDefine(K, V)                                     \
  static void HashmapIter(K, V)(Map(K, V) map, void(*iter_fn)(K,V)) \
  {                                                                 \
    hashmap_scan(map, HashmapIterImpl(K, V), iter_fn);              \
  }                                                                 \

#define HashmapDefine(K, V)                     \
  HashmapNewDefine(K, V)                        \
  HashmapPushDefine(K, V)                       \
  HashmapGetDefine(K, V)                        \
  HashmapRemoveDefine(K, V)                     \
  HashmapSizeDefine(K, V)                       \
  HashmapFreeDefine(K, V)                       \
  HashmapClearDefine(K, V)                      \
  HashmapIterImplDefine(K, V)                   \
  HashmapIterDefine(K, V)                       \
  static struct {                               \
    uint32_t key_size;                          \
    uint32_t val_size;                          \
    Map(K, V)(*new)();                          \
    void(*push)(Map(K,V),K,V);                  \
    V*(*get)(Map(K,V),K);                       \
    void(*remove)(Map(K,V),K);                  \
    size_t(*size)(Map(K,V));                    \
    void(*free)(Map(K,V));                      \
    void(*clear)(Map(K,V));                     \
    void(*iter)(Map(K,V), void(*iter_fn)(K,V)); \
  } Hashmap(K, V) = {                           \
    .key_size = sizeof(K),                      \
    .val_size = sizeof(V),                      \
    .new = HashmapNew(K,V),                     \
    .push = HashmapPush(K,V),                   \
    .get = HashmapGet(K,V),                     \
    .remove = HashmapRemove(K,V),               \
    .size = HashmapSize(K,V),                   \
    .free = HashmapFree(K,V),                   \
    .clear = HashmapClear(K,V),                 \
    .iter = HashmapIter(K,V),                   \
  };


#endif
