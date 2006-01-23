#include <string.h>

#include "alg-fst.h"
#include "rijndael.h"

long rijndael_decrypt_pad(rijndael_cipher* cipher,
			  const BYTE* input, long bytes, BYTE* output)
{
  int i, k, padLen;
  long blocks;
  uint8 block[RIJNDAEL_BYTESPERBLOCK];

  if (cipher == 0) return BAD_CIPHER_STATE;
  if (input == 0 || bytes <= 0) return 0; /* nothing to do */
  if (bytes % RIJNDAEL_BYTESPERBLOCK != 0) return BAD_DATA;
  blocks = bytes/RIJNDAEL_BYTESPERBLOCK;

  switch (cipher->mode) {
  case RIJNDAEL_ECB:
    /* all blocks but last */
    while (blocks > 1) {
      rijndaelDecrypt(cipher->rk, cipher->Nr, input, output);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
      --blocks;
    }
    /* last block */
    rijndaelDecrypt(cipher->rk, cipher->Nr, input, block);
    padLen = block[15];
    if (padLen >= RIJNDAEL_BYTESPERBLOCK) return BAD_DATA;
    for (i = RIJNDAEL_BYTESPERBLOCK - padLen; i < RIJNDAEL_BYTESPERBLOCK; i++)
      if (block[i] != padLen) return BAD_DATA;
    memcpy(output, block, RIJNDAEL_BYTESPERBLOCK - padLen);
    break;
		
  case RIJNDAEL_CBC:
    /* all blocks but last */
    while (blocks > 1) {
      rijndaelDecrypt(cipher->rk, cipher->Nr, input, block);
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK/32; k++)
	((uint32*)block)[k] ^= ((uint32*)cipher->IV)[k];
      memcpy(cipher->IV, input, RIJNDAEL_BYTESPERBLOCK);
      memcpy(output, block, RIJNDAEL_BYTESPERBLOCK);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
      --blocks;
    }
    /* last block */
    rijndaelDecrypt(cipher->rk, cipher->Nr, input, block);
    for (k = 0; k < RIJNDAEL_BITSPERBLOCK/32; k++)
      ((uint32*)block)[k] ^= ((uint32*)cipher->IV)[k];
    padLen = block[15];
    if (padLen <= 0 || padLen > RIJNDAEL_BYTESPERBLOCK) return BAD_DATA;
    for (i = RIJNDAEL_BYTESPERBLOCK - padLen; i < RIJNDAEL_BYTESPERBLOCK; i++)
      if (block[i] != padLen) return BAD_DATA;
    memcpy(output, block, RIJNDAEL_BYTESPERBLOCK - padLen);
    break;
	
  default:
    return BAD_CIPHER_STATE;
  }
	
  return bytes - padLen;
}
