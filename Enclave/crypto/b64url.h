
/**
 * `b64url.h' - b64url
 *
 * copyright (c) 2014 joseph werle
 */

#ifndef B64URL_H
#define B64URL_H 1

/**
 *  Memory allocation functions to use. You can define b64url_malloc and
 * b64url_realloc to custom functions if you want.
 */

#ifndef b64url_malloc
#  define b64url_malloc(ptr) malloc(ptr)
#endif
#ifndef b64url_realloc
#  define b64url_realloc(ptr, size) realloc(ptr, size)
#endif

/**
 * Base64 index table.
 */

static const char b64url_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '-', '_'
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode `unsigned char *' source with `size_t' size.
 * Returns a `char *' base64 encoded string.
 */

char *
b64url_encode (const unsigned char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string.
 */
unsigned char *
b64url_decode (const char *, size_t);

/**
 * Dencode `char *' source with `size_t' size.
 * Returns a `unsigned char *' base64 decoded string + size of decoded string.
 */
unsigned char *
b64url_decode_ex (const char *, size_t, size_t *);

#ifdef __cplusplus
}
#endif

#endif
