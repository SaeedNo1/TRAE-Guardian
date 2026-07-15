#define UNICODE
#define _UNICODE

#include "hash_table.h"
#include <string.h>

#define FNV1A_OFFSET 14695981039346656037ULL
#define FNV1A_PRIME 1099511628211ULL

uint64_t HashFNV1a64(const void* data, size_t len) {
    if (!data || len == 0) return 0;
    uint64_t hash = FNV1A_OFFSET;
    const uint8_t* bytes = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= FNV1A_PRIME;
    }
    return hash;
}

uint64_t HashCombine(uint64_t a, uint64_t b) {
    return a ^ (b + 0x9e3779b9 + (a << 6) + (a >> 2));
}

static uint32_t HashTableGetBucket(HashTable* ht, uint64_t key) {
    return (uint32_t)(key % ht->capacity);
}

static BOOL HashTableResize(HashTable* ht, uint32_t newCapacity) {
    if (!ht || newCapacity == 0) return FALSE;
    
    HashEntry** newBuckets = (HashEntry**)calloc(newCapacity, sizeof(HashEntry*));
    if (!newBuckets) return FALSE;
    
    for (uint32_t i = 0; i < ht->capacity; i++) {
        HashEntry* entry = ht->buckets[i];
        while (entry) {
            HashEntry* next = entry->next;
            uint32_t newBucket = (uint32_t)(entry->key % newCapacity);
            entry->next = newBuckets[newBucket];
            newBuckets[newBucket] = entry;
            entry = next;
        }
    }
    
    free(ht->buckets);
    ht->buckets = newBuckets;
    ht->capacity = newCapacity;
    return TRUE;
}

BOOL HashTableInit(HashTable* ht, void (*freeValue)(void*)) {
    if (!ht) return FALSE;
    memset(ht, 0, sizeof(HashTable));
    ht->buckets = (HashEntry**)calloc(HASH_TABLE_INITIAL_CAPACITY, sizeof(HashEntry*));
    if (!ht->buckets) return FALSE;
    ht->capacity = HASH_TABLE_INITIAL_CAPACITY;
    ht->size = 0;
    ht->freeValue = freeValue;
    InitializeCriticalSection(&ht->cs);
    return TRUE;
}

void HashTableCleanup(HashTable* ht) {
    if (!ht) return;
    EnterCriticalSection(&ht->cs);
    HashTableClear(ht);
    free(ht->buckets);
    ht->buckets = NULL;
    LeaveCriticalSection(&ht->cs);
    DeleteCriticalSection(&ht->cs);
}

BOOL HashTableInsert(HashTable* ht, uint64_t key, void* value) {
    if (!ht || !value) return FALSE;
    
    EnterCriticalSection(&ht->cs);
    
    if ((float)ht->size / (float)ht->capacity >= HASH_TABLE_MAX_LOAD_FACTOR) {
        if (!HashTableResize(ht, ht->capacity * 2)) {
            LeaveCriticalSection(&ht->cs);
            return FALSE;
        }
    }
    
    uint32_t bucket = HashTableGetBucket(ht, key);
    HashEntry* entry = ht->buckets[bucket];
    while (entry) {
        if (entry->key == key) {
            if (ht->freeValue && entry->value) {
                ht->freeValue(entry->value);
            }
            entry->value = value;
            LeaveCriticalSection(&ht->cs);
            return TRUE;
        }
        entry = entry->next;
    }
    
    HashEntry* newEntry = (HashEntry*)malloc(sizeof(HashEntry));
    if (!newEntry) {
        LeaveCriticalSection(&ht->cs);
        return FALSE;
    }
    newEntry->key = key;
    newEntry->value = value;
    newEntry->next = ht->buckets[bucket];
    ht->buckets[bucket] = newEntry;
    ht->size++;
    
    LeaveCriticalSection(&ht->cs);
    return TRUE;
}

void* HashTableGet(HashTable* ht, uint64_t key) {
    if (!ht) return NULL;
    
    EnterCriticalSection(&ht->cs);
    
    uint32_t bucket = HashTableGetBucket(ht, key);
    HashEntry* entry = ht->buckets[bucket];
    while (entry) {
        if (entry->key == key) {
            void* value = entry->value;
            LeaveCriticalSection(&ht->cs);
            return value;
        }
        entry = entry->next;
    }
    
    LeaveCriticalSection(&ht->cs);
    return NULL;
}

BOOL HashTableRemove(HashTable* ht, uint64_t key) {
    if (!ht) return FALSE;
    
    EnterCriticalSection(&ht->cs);
    
    uint32_t bucket = HashTableGetBucket(ht, key);
    HashEntry** pp = &ht->buckets[bucket];
    while (*pp) {
        HashEntry* entry = *pp;
        if (entry->key == key) {
            *pp = entry->next;
            if (ht->freeValue && entry->value) {
                ht->freeValue(entry->value);
            }
            free(entry);
            ht->size--;
            LeaveCriticalSection(&ht->cs);
            return TRUE;
        }
        pp = &entry->next;
    }
    
    LeaveCriticalSection(&ht->cs);
    return FALSE;
}

uint32_t HashTableSize(HashTable* ht) {
    if (!ht) return 0;
    EnterCriticalSection(&ht->cs);
    uint32_t size = ht->size;
    LeaveCriticalSection(&ht->cs);
    return size;
}

void HashTableClear(HashTable* ht) {
    if (!ht) return;
    
    for (uint32_t i = 0; i < ht->capacity; i++) {
        HashEntry* entry = ht->buckets[i];
        while (entry) {
            HashEntry* next = entry->next;
            if (ht->freeValue && entry->value) {
                ht->freeValue(entry->value);
            }
            free(entry);
            entry = next;
        }
        ht->buckets[i] = NULL;
    }
    ht->size = 0;
}

void HashTableIterate(HashTable* ht, HashTableIterator callback, void* context) {
    if (!ht || !callback) return;
    
    EnterCriticalSection(&ht->cs);
    
    for (uint32_t i = 0; i < ht->capacity; i++) {
        HashEntry* entry = ht->buckets[i];
        while (entry) {
            callback(entry->key, entry->value, context);
            entry = entry->next;
        }
    }
    
    LeaveCriticalSection(&ht->cs);
}