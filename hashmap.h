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

#define CAT2(a,b) a##b
#define CAT(a,b) CAT2(a,b)

#ifdef _WIN32
#define __HM_UNUSED__
#elif defined(__GNUC__)
#define __HM_UNUSED__ __attribute__((unused))
#else
#error("Unsupported Compiler")
#endif

#define HashFunction(K) CAT(HashFunction_,K)
#define CmpFunction(K)  CAT(CmpFunction_,K)

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

#define Hashmap(K, V) CAT(CAT(CAT(HashmapStruct_, K), _), V)

#define HashmapEntry(K, V) CAT(CAT(CAT(HashmapEntryStruct_, K), _), V)
#define HashmapEntryDefine(K, V) typedef struct { K key; V value; } HashmapEntry(K,V);

#define HashmapMethod(K,V,Name)   CAT(CAT(CAT(CAT(CAT(CAT(Hashmap,Name),_),K),_),V),_Method)
#define HashmapFunction(K,V,Name) CAT(CAT(CAT(CAT(CAT(CAT(Hashmap,Name),_),K),_),V),_Function)
#define HashmapDestructor(K,V)    CAT(CAT(CAT(CAT(CAT(CAT(Hashmap,Name),_),K),_),V),_Destructor)

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

#define HashmapFreeDefine(K, V)            \
  __HM_UNUSED__ static void                \
  HashmapMethod(K, V, Free)(Map(K, V) map) \
  {                                        \
    HashmapMethod(K, V, Clear)(map);       \
    hashmap_free(map);                     \
  }

#define HashmapClearDefine(K, V)             \
  __HM_UNUSED__ static bool                  \
  destroyEach(const void *data, void *udata) \
  {                                          \
    HashmapDestructor(K, V)(data);           \
    return true;                             \
  }                                          \
  __HM_UNUSED__ static void                  \
  HashmapMethod(K, V, Clear)(Map(K, V) map)  \
  {                                          \
    hashmap_scan(map, destroyEach, NULL);    \
    hashmap_clear(map, false);               \
  }

#define HashmapIterImplDefine(K, V)                                \
  __HM_UNUSED__ static bool                                        \
  HashmapFunction(K, V, IterImpl)(const void *data, void* iter_fn) \
  {                                                                \
    const HashmapEntry(K, V) *entry = data;                        \
    ((void(*)(K,V))iter_fn)(entry->key, entry->value);             \
    return true;                                                   \
  }

#define HashmapIterDefine(K, V)                                  \
  __HM_UNUSED__ static void                                      \
  HashmapMethod(K, V, Iter)(Map(K, V) map, void(*iter_fn)(K,V))  \
  {                                                              \
    hashmap_scan(map, HashmapFunction(K, V, IterImpl), iter_fn); \
  }                                                              \

#define HashmapDestructorDefine(K, V, K_destr, V_destr)   \
  __HM_UNUSED__ static inline void                        \
  HashmapDestructor(K, V)(const HashmapEntry(K,V) *entry) \
  {                                                       \
    if(K_destr) ((void(*)(K))K_destr)(entry->key);        \
    if(V_destr) ((void(*)(V))V_destr)(entry->value);      \
  }

// Both are the same for now, might need to change?
#define HashmapMethodDefine(K, V, Name)   CAT(CAT(Hashmap, Name), Define)(K, V)
#define HashmapFunctionDefine(K, V, Name) CAT(CAT(Hashmap, Name), Define)(K, V)

#define VARGS_NARG(...) VARGS_NARG_IMPL(__VA_ARGS__, VARGS_RSEQ_N())
#define VARGS_NARG_IMPL(...) VARGS_ARG_N(__VA_ARGS__)
#define VARGS_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14, _15, N, ...) N
#define VARGS_RSEQ_N() 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

#define HashmapDefine(...) CAT(__HashmapDefine_IMPL_,VARGS_NARG(__VA_ARGS__))(__VA_ARGS__)

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


#endif
