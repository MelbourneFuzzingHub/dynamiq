#include "afl-fuzz.h"
#include <stdlib.h>
#include <string.h>

hash_set_t *hash_set_new() {
    hash_set_t *new_set = (hash_set_t *)malloc(sizeof(hash_set_t));
    if (!new_set) {
        return NULL;
    }
    new_set->set = NULL;  // Initialize to NULL (required for uthash)
    return new_set;
}

int hash_set_contains(hash_set_t *set, const char *hash_value) {
    hash_entry_t *entry;
    HASH_FIND_STR(set->set, hash_value, entry);  // Find the entry in the hash set
    return entry != NULL;  // Return 1 if found, 0 otherwise
}

void hash_set_insert(hash_set_t *set, const char *hash_value) {
    hash_entry_t *entry = (hash_entry_t *)malloc(sizeof(hash_entry_t));
    if (entry == NULL) {
        return;  // Handle memory allocation failure
    }
    strcpy(entry->hash_value, hash_value);  // Copy the hash value
    HASH_ADD_STR(set->set, hash_value, entry);  // Add the entry to the hash set
}

void hash_set_free(hash_set_t *set) {
    hash_entry_t *entry, *tmp;
    HASH_ITER(hh, set->set, entry, tmp) {
        HASH_DEL(set->set, entry);  // Remove entry from hash set
        free(entry);  // Free memory for the entry
    }
    free(set);  // Free the hash set itself
}

// u8 *get_test_case_hash(const char *file_name) {
//     size_t len = strlen(file_name);
//     ssize_t i = len - 1;

//     // Efficient reverse scan to strip -<number> suffix
//     while (i > 0 && isdigit((unsigned char)file_name[i])) i--;
//     if (file_name[i] == '-' && i > 0) {
//         len = (size_t)i;  // Truncate before the '-'
//     }

//     // Allocate memory for truncated string
//     u8 *hash = (u8 *)malloc(len + 1);
//     if (!hash) return NULL;

//     strncpy((char *)hash, file_name, len);
//     hash[len] = '\0';

//     return hash;
// }

/* Return malloc'ed dedupe key:
   - If the basename ends with "-<digits>" AND the char before '-' is a digit,
     return SHA1 of the TRUNCATED BASENAME string.
   - Otherwise, return SHA1 of the FULL BASENAME string.
*/
u8 *get_test_case_hash(const char *file_name) {

  if (!file_name) return NULL;

  size_t blen = strlen(file_name);
  if (blen > 2) {
    ssize_t i = (ssize_t)blen - 1;
    while (i > 0 && isdigit((unsigned char)file_name[i])) i--;
    if (i > 0 && file_name[i] == '-' && isdigit((unsigned char)file_name[i - 1])) {
      /* Truncate [0..i) and hash it */
      size_t trunc_len = (size_t)i;
      return (u8 *)sha1_hex((const u8 *)file_name, trunc_len);
    }
  }

  /* Default: hash the full basename */
  return (u8 *)sha1_hex((const u8 *)file_name, blen);
}