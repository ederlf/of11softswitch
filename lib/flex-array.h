#ifndef FLEX_ARRAY_H
#define FLEX_ARRAY_H 1

#include <stdint.h>

/*A flexible array structure */
struct flex_array {

   uint16_t size;  /* Array size */
   uint16_t total; /* Number of entries */
   uint8_t pad[4];  /* Allign to 64 bits */
   uint8_t entries[]; /* */
         
};

#endif /* flex-array.h */
