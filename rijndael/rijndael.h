#ifndef RIJNDAEL__H__
#define RIJNDAEL__H__

#include "alg-fst.h"

/*  Generic Defines  */
#define RIJNDAEL_ENCRYPT 0	/* Are we encrypting? */
#define RIJNDAEL_DECRYPT 1	/* Are we decrypting? */
#define RIJNDAEL_ECB 1		/* ECB mode */
#define RIJNDAEL_CBC 2		/* CBC mode */
#define RIJNDAEL_CFB1 3		/* 1-bit CFB mode */
#define RIJNDAEL_BITSPERBLOCK 128 /* Default number of bits in a cipher block */
#define RIJNDAEL_BYTESPERBLOCK (RIJNDAEL_BITSPERBLOCK/8)

/*  Error Codes  */
#define     BAD_KEY_DIR          -1 /*  Key direction is invalid, e.g., unknown value */
#define     BAD_KEY_MAT          -2 /*  Key material not of correct length */
#define     BAD_KEY_INSTANCE     -3 /*  Key passed is not valid */
#define     BAD_CIPHER_MODE      -4 /*  Params struct passed to cipherInit invalid */
#define     BAD_CIPHER_STATE     -5 /*  Cipher in wrong state (e.g., not initialized) */
#define     BAD_BLOCK_LENGTH     -6
#define     BAD_CIPHER_INSTANCE  -7
#define     BAD_DATA             -8 /*  Data contents are invalid, e.g., invalid padding */
#define     BAD_OTHER            -9 /*  Unknown error */

/*  Algorithm-specific Defines  */
#define     MAX_KEY_SIZE         32 /* # of bytes needed to represent a key */
#define     MAX_IV_SIZE          RIJNDAEL_BYTESPERBLOCK /* # bytes needed to represent an IV  */

typedef unsigned char BYTE;

/*  The structure for cipher and key information */
typedef struct {
  int mode;			/* MODE_ECB, MODE_CBC, or MODE_CFB1 */
  int keylen;			/* Length of the key  */
  int Nr;                       /* key-length-dependent number of rounds */
  uint32 rk[4*(MAXNR + 1)];	/* key schedule */
  uint32 ek[4*(MAXNR + 1)];	/* CFB1 key schedule (encryption only) */
  BYTE IV[MAX_IV_SIZE];		/* A possible Initialization Vector for ciphering */
} rijndael_cipher;

/*  Function prototypes  */

int rijndael_init(rijndael_cipher* cipher,
		  int direction, int keylen, const BYTE* key,
		  int mode, const BYTE* IV);

long rijndael_encrypt_blocks(rijndael_cipher* cipher,
			     const BYTE* input, long bytes, BYTE* output);

long rijndael_encrypt_pad(rijndael_cipher* cipher,
			  const BYTE* input, long bytes, BYTE* output);

long rijndael_decrypt_blocks(rijndael_cipher* cipher,
			     const BYTE* input, long bytes, BYTE* output);

long rijndael_decrypt_pad(rijndael_cipher* cipher,
			  const BYTE* input, long bytes, BYTE* output);

#endif
