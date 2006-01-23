#include <string.h>

#include "alg-fst.h"
#include "rijndael.h"

long rijndael_decrypt_blocks(rijndael_cipher* cipher,
			     const BYTE* input, long bytes, BYTE* output)
{
  int i, k, t, blocks;
  uint8 block[16], *iv;

  if (cipher == 0) return BAD_CIPHER_STATE;
  if (input == 0 || bytes <= 0) return 0; /* nothing to do */
  if (bytes%RIJNDAEL_BYTESPERBLOCK != 0) return BAD_DATA;
  blocks = bytes/RIJNDAEL_BYTESPERBLOCK;

  switch (cipher->mode) {
  case RIJNDAEL_ECB:
    for (i = blocks; i > 0; i--) {
      rijndaelDecrypt(cipher->rk, cipher->Nr, input, output);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
    }
    break;
		
  case RIJNDAEL_CBC:
    iv = cipher->IV;
    for (i = blocks; i > 0; i--) {
      rijndaelDecrypt(cipher->rk, cipher->Nr, input, block);
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK/32; k++)
	((uint32*)block)[k] ^= ((uint32*)iv)[k];
      memcpy(cipher->IV, input, RIJNDAEL_BYTESPERBLOCK);
      memcpy(output, block, RIJNDAEL_BYTESPERBLOCK);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
    }
    break;

  case RIJNDAEL_CFB1:
    iv = cipher->IV;
    for (i = blocks; i > 0; i--) {
      memcpy(output, input, RIJNDAEL_BYTESPERBLOCK);
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK; k++) {
	rijndaelEncrypt(cipher->ek, cipher->Nr, iv, block);
	for (t = 0; t < RIJNDAEL_BYTESPERBLOCK-1; t++) {
	  iv[t] = (iv[t] << 1) | (iv[t + 1] >> 7);
	}
	iv[RIJNDAEL_BYTESPERBLOCK-1] =
	  (iv[RIJNDAEL_BYTESPERBLOCK-1] << 1) |
	  ((input[k >> 3] >> (7 - (k & 7))) & 1);
	output[k >> 3] ^= (block[0] & 0x80U) >> (k & 7);
      }
      output += RIJNDAEL_BYTESPERBLOCK;
      input += RIJNDAEL_BYTESPERBLOCK;
    }
    break;
    
  default:
    return BAD_CIPHER_STATE;
  }
	
  return RIJNDAEL_BYTESPERBLOCK*blocks;
}
