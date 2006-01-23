#include <string.h>

#include "alg-fst.h"
#include "rijndael.h"

/**
 * Encrypt data partitioned in octets, using RFC 2040-like padding.
 *
 * @param   input           data to be encrypted (octet sequence)
 * @param   bytes           input length in octets (not bits)
 * @param   output          encrypted output data
 *
 * @return	length in octets (not bits) of the encrypted output buffer.
 */
long rijndael_encrypt_pad(rijndael_cipher* cipher,
			  const BYTE *input, long bytes, BYTE *output)
{
  int i, k, padLen;
  long blocks;
  uint8 block[RIJNDAEL_BYTESPERBLOCK], *iv;

  if (cipher == 0) return BAD_CIPHER_STATE;
  if (input == 0 || bytes <= 0) return 0; /* nothing to do */
  blocks = bytes/RIJNDAEL_BYTESPERBLOCK;
  padLen = RIJNDAEL_BYTESPERBLOCK - (bytes - blocks*RIJNDAEL_BYTESPERBLOCK);
  /* assert(padLen > 0 && padLen <= RIJNDAEL_BYTESPERBLOCK); */

  switch (cipher->mode) {
  case RIJNDAEL_ECB:
    for (i = blocks; i > 0; i--) {
      rijndaelEncrypt(cipher->rk, cipher->Nr, input, output);
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
    }
    memcpy(block, input, RIJNDAEL_BYTESPERBLOCK - padLen);
    memset(block + RIJNDAEL_BYTESPERBLOCK - padLen, padLen, padLen);
    rijndaelEncrypt(cipher->rk, cipher->Nr, block, output);
    break;

  case RIJNDAEL_CBC:
    iv = cipher->IV;
    for (i = blocks; i > 0; i--) {
      for (k = 0; k < RIJNDAEL_BITSPERBLOCK/32; k++)
	((uint32*)block)[k] = ((uint32*)input)[k] ^ ((uint32*)iv)[k];
      rijndaelEncrypt(cipher->rk, cipher->Nr, block, output);
      iv = output;
      input += RIJNDAEL_BYTESPERBLOCK;
      output += RIJNDAEL_BYTESPERBLOCK;
    }
    for (i = 0; i < RIJNDAEL_BYTESPERBLOCK - padLen; i++)
      block[i] = input[i] ^ iv[i];
    for (i = RIJNDAEL_BYTESPERBLOCK - padLen; i < RIJNDAEL_BYTESPERBLOCK; i++)
      block[i] = (BYTE)padLen ^ iv[i];
    rijndaelEncrypt(cipher->rk, cipher->Nr, block, output);
    memcpy(cipher->IV, iv, RIJNDAEL_BYTESPERBLOCK);
    break;
    
  default:
    return BAD_CIPHER_STATE;
  }
  
  return RIJNDAEL_BYTESPERBLOCK * (blocks+1);
}
