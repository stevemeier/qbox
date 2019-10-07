/* Source: https://stackoverflow.com/questions/51053568/generating-a-random-uuid-in-c */
/* Requires libuuid-devel on RHEL7/8 */

/* For malloc() */
#include <stdlib.h>
/* For puts()/printf() */
#include <stdio.h>
/* For uuid_generate() and uuid_unparse() */
#include <uuid/uuid.h>

/* Uncomment to always generate capital UUIDs. */
//#define capitaluuid true

/* Uncomment to always generate lower-case UUIDs. */
#define lowercaseuuid true

/*
 * Don't uncomment either if you don't care (the case of the letters
 * in the 'unparsed' UUID will depend on your system's locale).
 */

int main(void) {
    uuid_t binuuid;
    /*
     * Generate a UUID. We're not done yet, though,
     * for the UUID generated is in binary format
     * (hence the variable name). We must 'unparse'
     * binuuid to get a usable 36-character string.
     */
    uuid_generate_random(binuuid);

    /*
     * uuid_unparse() doesn't allocate memory for itself, so do that with
     * malloc(). 37 is the length of a UUID (36 characters), plus '\0'.
     */
    char *uuid = malloc(37);

#ifdef capitaluuid
    /* Produces a UUID string at uuid consisting of capital letters. */
    uuid_unparse_upper(binuuid, uuid);
#elif lowercaseuuid
    /* Produces a UUID string at uuid consisting of lower-case letters. */
    uuid_unparse_lower(binuuid, uuid);
#else
    /*
     * Produces a UUID string at uuid consisting of letters
     * whose case depends on the system's locale.
     */
    uuid_unparse(binuuid, uuid);
#endif

    printf("Ssessionid=%s\n", uuid);

    return 0;
}
