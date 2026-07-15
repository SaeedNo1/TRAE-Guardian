#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

#define HASH_TABLE_INITIAL_CAPACITY 64
#define HASH_TABLE_MAX_LOAD_FACTOR 0.75f

typedef struct HashEntry {
    uint64_t key;
    void* value;
    struct HashEntry* next;
} HashEntry;

typedef struct {
    HashEntry** buckets;
    uint32_t capacity;
    uint32_t size;
    CRITICAL_SECTION cs;
    void (*freeValue)(void*);
} HashTable;

uint64_t HashFNV1a64(const void* data, size_t len);
uint64_t HashCombine(uint64_t a, uint64_t b);

BOOL HashTableInit(HashTable* ht, void (*freeValue)(void*));
void HashTableCleanup(HashTable* ht);
BOOL HashTableInsert(HashTable* ht, uint64_t key, void* value);
void* HashTableGet(HashTable* ht, uint64_t key);
BOOL HashTableRemove(HashTable* ht, uint64_t key);
uint32_t HashTableSize(HashTable* ht);
void HashTableClear(HashTable* ht);

typedef void (*HashTableIterator)(uint64_t key, void* value, void* context);
void HashTableIterate(HashTable* ht, HashTableIterator callback, void* context);

#endif