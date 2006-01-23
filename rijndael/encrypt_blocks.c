#include <string.h>

#include "alg-fst.h"
#include "rijndael.h"

long rijndael_encrypt_blocks(rijndael_cipher* cipher,
			     const BYTE* input, long bytes, BYTE* output)
{
  int k, t;
  long blocks;
  uint8 block[RIJNDAEL_BYTESPERBLOCK], *iv;

  if (cipher == 0) return BAD_CIPHER_STATE;
  if (input == 0 || bytes <= 0) return 0; /* nothing to do */
  if (bytes % RIJNDAEL_BYTESPERBLOCK != 0) return BAD_DATA;
  
  blocks = bytes/RIJNDAEL_BYTESPERBLOCK;
	
  switch (cipher->mode) {
  case RIJNDAEL_ECB:
    while (blocks > 0) {
      rijndaelEncrypt(cipher->rk, cipher->Nr, input, output);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
      --blocks;
    }
    break;
		
  case RIJNDAEL_CBC:
    iv = cipher->IV;
    while (blocks > 0) {
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK/32; k++)
	((uint32*)block)[k] = ((uint32*)input)[k] ^ ((uint32*)iv)[k];
      rijndaelEncrypt(cipher->rk, cipher->Nr, block, output);
      iv = output;
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
      --blocks;
    }
    memcpy(cipher->IV, iv, RIJNDAEL_BYTESPERBLOCK);
    break;

  case RIJNDAEL_CFB1:
    iv = cipher->IV;
    while (blocks > 0) {
      memcpy(output, input, RIJNDAEL_BYTESPERBLOCK);
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK; k++) {
	rijndaelEncrypt(cipher->ek, cipher->Nr, iv, block);
	output[k >> 3] ^= (block[0] & 0x80U) >> (k & 7);
	for (t = 0; t < RIJNDAEL_BYTESPERBLOCK-1; t++)
	  iv[t] = (iv[t] << 1) | (iv[t + 1] >> 7);
	iv[RIJNDAEL_BYTESPERBLOCK-1] =
	  (iv[RIJNDAEL_BYTESPERBLOCK-1] << 1) |
	  ((output[k >> 3] >> (7 - (k & 7))) & 1);
      }
      output += RIJNDAEL_BYTESPERBLOCK;
      input += RIJNDAEL_BYTESPERBLOCK;
      --blocks;
    }
    break;
    
  default:
    return BAD_CIPHER_STATE;
  }
	
  return bytes;
}
