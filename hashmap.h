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

#define __HM_CAT2(a,b) a##b
#define __HM_CAT(a,b) __HM_CAT2(a,b)

#ifdef _WIN32
#define __HM_UNUSED__
#elif defined(__GNUC__)
#define __HM_UNUSED__ __attribute__((unused))
#else
#error("Unsupported Compiler")
#endif

#define HashFunction(K) __HM_CAT(HashFunction_,K)
#define CmpFunction(K)  __HM_CAT(CmpFunction_,K)

#define HashFunctionDefineCustom(K, pVar) \
  __HM_UNUSED__ static uint64_t           \
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
  __HM_UNUSED__ static int                       \
  CmpFunction(K)(                                \
      const K* pVar0,                            \
      const K* pVar1,                            \
      void *udata)

#define CmpFunctionDefine(K)                 \
  CmpFunctionDefineCustom(K, pItem0, pItem1) \
  { (void)udata;                             \
    return memcmp(pItem0, pItem1, sizeof(K));\
  }

#define Map(K, V) struct hashmap *

#define Hashmap(K, V) __HM_CAT(__HM_CAT(__HM_CAT(HashmapStruct_, K), _), V)

#define HashmapEntry(K, V) __HM_CAT(__HM_CAT(__HM_CAT(HashmapEntryStruct_, K), _), V)
#define HashmapEntryDefine(K, V) typedef struct { K key; V value; } HashmapEntry(K,V);

#define HashmapMethod(K,V,Name)   __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashmap,Name),_),K),_),V),_Method)
#define HashmapFunction(K,V,Name) __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashmap,Name),_),K),_),V),_Function)
#define HashmapDestructor(K,V)    __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashmap,Name),_),K),_),V),_Destructor)

#define HashmapNewDefine(K, V)       \
  __HM_UNUSED__ static Map(K, V)     \
  HashmapMethod(K, V, New)()         \
  {                                  \
    return hashmap_new(              \
        sizeof(K) + sizeof(V),       \
        0, 0, 0,                     \
        (hm_hash_fn)HashFunction(K), \
        (hm_cmp_fn)CmpFunction(K),   \
        NULL);                       \
  }

#define HashmapPushDefine(K, V)                          \
  __HM_UNUSED__ static void                              \
  HashmapMethod(K, V, Push)(Map(K, V) map, K key, V val) \
  {                                                      \
    HashmapEntry(K, V) entry = {key, val};               \
    HashmapEntry(K, V) *prev = hashmap_set(map, &entry); \
    if(prev) {                                           \
      HashmapDestructor(K,V)(prev);                      \
    }                                                    \
  }

#define HashmapGetDefine(K, V)                          \
  __HM_UNUSED__ static V*                               \
  HashmapMethod(K, V, Get)(Map(K, V) map, K key)        \
  {                                                     \
    HashmapEntry(K, V) entry = {.key = key};            \
    HashmapEntry(K, V) *res = hashmap_get(map, &entry); \
    if(res) {                                           \
      return &(res->value);                             \
    }                                                   \
    return NULL;                                        \
  }

#define HashmapRemoveDefine(K, V)                          \
  __HM_UNUSED__ static void                                \
  HashmapMethod(K, V, Remove)(Map(K, V) map, K key)        \
  {                                                        \
    HashmapEntry(K, V) entry = {.key = key};               \
    HashmapEntry(K, V) *old = hashmap_delete(map, &entry); \
    if(old) {                                              \
      HashmapDestructor(K, V)(old);                        \
    }                                                      \
  }

#define HashmapSizeDefine(K, V)            \
  __HM_UNUSED__ static size_t              \
  HashmapMethod(K, V, Size)(Map(K, V) map) \
  {                                        \
    return hashmap_count(map);             \
  }

#define HashmapClearDefine(K, V)             \
  __HM_UNUSED__ static bool                  \
  HashmapFunction(K, V, destroyEach)(const void *data, void *udata) \
  {                                          \
    (void)udata;                             \
    HashmapDestructor(K, V)(data);           \
    return true;                             \
  }                                          \
  __HM_UNUSED__ static void                  \
  HashmapMethod(K, V, Clear)(Map(K, V) map)  \
  {                                          \
    hashmap_scan(map, HashmapFunction(K, V, destroyEach), NULL);    \
    hashmap_clear(map, false);               \
  }

#define HashmapFreeDefine(K, V)            \
  __HM_UNUSED__ static void                \
  HashmapMethod(K, V, Free)(Map(K, V) map) \
  {                                        \
    HashmapMethod(K, V, Clear)(map);       \
    hashmap_free(map);                     \
  }

#define HashmapIterImplDefine(K, V)                                      \
  __HM_UNUSED__ static bool                                              \
  HashmapFunction(K, V, IterImpl)(const void *data, void(*iter_fn)(K,V)) \
  {                                                                      \
    const HashmapEntry(K, V) *entry = data;                              \
    iter_fn(entry->key, entry->value);                                   \
    return true;                                                         \
  }

#define HashmapIterDefine(K, V)                                  \
  __HM_UNUSED__ static void                                      \
  HashmapMethod(K, V, Iter)(Map(K, V) map, void(*iter_fn)(K,V))  \
  {                                                              \
    hashmap_scan(map, (bool(*)(const void*, void*))HashmapFunction(K, V, IterImpl), (void*)iter_fn); \
  }                                                              \

#define HashmapDestructorDefine(K, V, K_destr, V_destr)   \
  __HM_UNUSED__ static inline void                        \
  HashmapDestructor(K, V)(const HashmapEntry(K,V) *entry) \
  {                                                       \
    if(K_destr) ((void(*)(K))K_destr)(entry->key);        \
    if(V_destr) ((void(*)(V))V_destr)(entry->value);      \
  }

// Both are the same for now, might need to change?
#define HashmapMethodDefine(K, V, Name)   __HM_CAT(__HM_CAT(Hashmap, Name), Define)(K, V)
#define HashmapFunctionDefine(K, V, Name) __HM_CAT(__HM_CAT(Hashmap, Name), Define)(K, V)

#define VARGS_NARG(...) VARGS_NARG_IMPL(__VA_ARGS__, VARGS_RSEQ_N())
#define VARGS_NARG_IMPL(...) VARGS_ARG_N(__VA_ARGS__)
#define VARGS_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, N, ...) N
#define VARGS_RSEQ_N() 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#define HashmapDefine(...) __HM_CAT(__HashmapDefine_IMPL_,VARGS_NARG(__VA_ARGS__))(__VA_ARGS__)

#define __HashmapDefine_IMPL_1(x) static_assert("Can't define a hashmap with a single type. Need (Key,Val) typepair");
#define __HashmapDefine_IMPL_2(K, V) __HashmapDefine_IMPL_4(K, V, NULL, NULL)
#define __HashmapDefine_IMPL_3(K, V, destr) __HashmapDefine_IMPL_4(K, V, destr, destr)

#define __HashmapDefine_IMPL_4(K, V, K_destr, V_destr)     \
  HashmapEntryDefine(K, V)                        \
  HashmapDestructorDefine(K, V, K_destr, V_destr) \
  HashmapMethodDefine(K, V, New)                  \
  HashmapMethodDefine(K, V, Push)                 \
  HashmapMethodDefine(K, V, Get)                  \
  HashmapMethodDefine(K, V, Remove)               \
  HashmapMethodDefine(K, V, Size)                 \
  HashmapMethodDefine(K, V, Clear)                \
  HashmapMethodDefine(K, V, Free)                 \
  HashmapFunctionDefine(K, V, IterImpl)           \
  HashmapMethodDefine(K, V, Iter)                 \
  static struct {                                 \
    uint32_t key_size;                            \
    uint32_t val_size;                            \
    Map(K, V)(*new)();                            \
    void(*push)(Map(K,V),K,V);                    \
    V*(*get)(Map(K,V),K);                         \
    void(*remove)(Map(K,V),K);                    \
    size_t(*size)(Map(K,V));                      \
    void(*free)(Map(K,V));                        \
    void(*clear)(Map(K,V));                       \
    void(*iter)(Map(K,V), void(*iter_fn)(K,V));   \
  } Hashmap(K, V) = {                             \
    .key_size  = sizeof(K),                       \
    .val_size  = sizeof(V),                       \
    .new       = HashmapMethod(K,V,New),          \
    .push      = HashmapMethod(K,V,Push),         \
    .get       = HashmapMethod(K,V,Get),          \
    .remove    = HashmapMethod(K,V,Remove),       \
    .size      = HashmapMethod(K,V,Size),         \
    .free      = HashmapMethod(K,V,Free),         \
    .clear     = HashmapMethod(K,V,Clear),        \
    .iter      = HashmapMethod(K,V,Iter),         \
  };

#define __HashmapDefine_IMPL_5(...)  static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_6(...)  static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_7(...)  static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_8(...)  static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_9(...)  static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_10(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_11(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_12(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_13(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_14(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");
#define __HashmapDefine_IMPL_15(...) static_assert("Passed too many arguments to HashmapDefine. Accepted argument counts are (2, 3, 4).");

// TODO: Prefix the entire API
// Commented because it collides with some C++ files in MSVC
// #define Set(K) struct hashmap *
#define Hashset(K) __HM_CAT(HashsetStruct_, K)

#define HashsetMethod(K,Name)   __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashset,Name),_),K),_Method)
#define HashsetFunction(K,Name) __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashset,Name),_),K),_Function)
#define HashsetDestructor(K)    __HM_CAT(__HM_CAT(__HM_CAT(__HM_CAT(Hashset,Name),_),K),_Destructor)

#define HashsetNewDefine(K)          \
  __HM_UNUSED__ static Set(K)        \
  HashsetMethod(K, New)()            \
  {                                  \
    return hashmap_new(              \
        sizeof(K),                   \
        0, 0, 0,                     \
        (hm_hash_fn)HashFunction(K), \
        (hm_cmp_fn)CmpFunction(K),   \
        NULL);                       \
  }

#define HashsetPushDefine(K)                \
  __HM_UNUSED__ static void                 \
  HashsetMethod(K, Push)(Set(K) set, K key) \
  {                                         \
    K *prev = hashmap_set(set, &key);       \
    if(prev) {                              \
      HashsetDestructor(K)(prev);           \
    }                                       \
  }

#define HashsetRemoveDefine(K)                \
  __HM_UNUSED__ static void                   \
  HashsetMethod(K, Remove)(Set(K) set, K key) \
  {                                           \
    K *old = hashmap_delete(set, &key);       \
    if(old) {                                 \
      HashsetDestructor(K)(old);              \
    }                                         \
  }

#define HashsetClearDefine(K)                \
  __HM_UNUSED__ static bool                  \
  HashsetFunction(K, destroyEach)(const void *data, void *udata) \
  {                                          \
    (void)udata;                             \
    HashsetDestructor(K)(data);              \
    return true;                             \
  }                                          \
  __HM_UNUSED__ static void                  \
  HashsetMethod(K, Clear)(Set(K) set)        \
  {                                          \
    hashmap_scan(set, HashsetFunction(K, destroyEach), NULL);    \
    hashmap_clear(set, false);               \
  }

#define HashsetFreeDefine(K)         \
  __HM_UNUSED__ static void          \
  HashsetMethod(K, Free)(Set(K) set) \
  {                                  \
    HashsetMethod(K, Clear)(set);    \
    hashmap_free(set);               \
  }

#define HashsetSizeDefine(K)         \
  __HM_UNUSED__ static size_t        \
  HashsetMethod(K, Size)(Set(K) set) \
  {                                  \
    return hashmap_count(set);       \
  }

#define HashsetIterImplDefine(K)                                \
  __HM_UNUSED__ static bool                                     \
  HashsetFunction(K, IterImpl)(const void *data, void* iter_fn) \
  {                                                             \
    ((void(*)(K))iter_fn)(*(K*)data);                           \
    return true;                                                \
  }

#define HashsetIterDefine(K)                                  \
  __HM_UNUSED__ static void                                   \
  HashsetMethod(K, Iter)(Set(K) set, void(*iter_fn)(K))       \
  {                                                           \
    hashmap_scan(set, HashsetFunction(K, IterImpl), iter_fn); \
  }                                                           \

#define HashsetDestructorDefine(K, K_destr)  \
  __HM_UNUSED__ static inline void           \
  HashsetDestructor(K)(const K *key)         \
  {                                          \
    if(K_destr) ((void(*)(K))K_destr)(*key); \
  }

#define HashsetHasDefine(K)                  \
  __HM_UNUSED__ static bool                  \
  HashsetMethod(K, Get)(Set(K) set, K key)   \
  {                                          \
    HashmapEntry(K, V) entry = {.key = key}; \
    return (bool) hashmap_get(set, &key);    \
  }

#define HashsetMethodDefine(K, Name)   __HM_CAT(__HM_CAT(Hashset, Name), Define)(K)
#define HashsetFunctionDefine(K, Name) __HM_CAT(__HM_CAT(Hashset, Name), Define)(K)

#define HashsetDefine(...) __HM_CAT(__HashsetDefine_IMPL_,VARGS_NARG(__VA_ARGS__))(__VA_ARGS__)

#define __HashsetDefine_IMPL_1(K) __HashsetDefine_IMPL_2(K, NULL)
#define __HashsetDefine_IMPL_2(K, destr)    \
  HashsetEntryDefine(K)                     \
  HashsetDestructorDefine(K, K_destr)       \
  HashsetMethodDefine(K, New)               \
  HashsetMethodDefine(K, Push)              \
  HashsetMethodDefine(K, Remove)            \
  HashsetMethodDefine(K, Size)              \
  HashsetMethodDefine(K, Clear)             \
  HashsetMethodDefine(K, Free)              \
  HashsetFunctionDefine(K, IterImpl)        \
  HashsetMethodDefine(K, Iter)              \
  HashsetMethodDefine(K, Has)               \
  static struct {                           \
    uint32_t key_size;                      \
    Set(K)(*new)();                         \
    void(*push)(Set(K),K);                  \
    void(*remove)(Set(K),K);                \
    size_t(*size)(Set(K));                  \
    void(*free)(Set(K));                    \
    void(*clear)(Set(K));                   \
    void(*iter)(Set(K), void(*iter_fn)(K)); \
    bool(*has)(Set(K),K);                   \
  } Hashset(K) = {                          \
    .key_size  = sizeof(K),                 \
    .new       = HashsetMethod(K,New),      \
    .push      = HashsetMethod(K,Push),     \
    .remove    = HashsetMethod(K,Remove),   \
    .size      = HashsetMethod(K,Size),     \
    .free      = HashsetMethod(K,Free),     \
    .clear     = HashsetMethod(K,Clear),    \
    .iter      = HashsetMethod(K,Iter),     \
    .has = HashsetMethod(K, has),           \
  };

#define __HashsetDefine_IMPL_3(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_4(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_5(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_6(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_7(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_8(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_9(...)  static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_10(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_11(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_12(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_13(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_14(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");
#define __HashsetDefine_IMPL_15(...) static_assert("Passed too many arguments to HashsetDefine. Accepted argument counts are (1, 2).");

#endif
