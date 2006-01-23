#include <string.h>

#include "alg-fst.h"
#include "rijndael.h"

int rijndael_init(rijndael_cipher* cipher,
		  int direction, int keylen, const BYTE* key,
		  int mode, const BYTE* IV)
{
  if ((direction != RIJNDAEL_ENCRYPT) &&
      (direction != RIJNDAEL_DECRYPT))
    return BAD_KEY_DIR;

  if ((mode != RIJNDAEL_ECB) &&
      (mode != RIJNDAEL_CBC) &&
      (mode != RIJNDAEL_CFB1))
    return BAD_CIPHER_MODE;
  cipher->mode = mode;

  keylen *= 8;
  if ((keylen != 128) && (keylen != 192) && (keylen != 256))
    return BAD_KEY_MAT;
  cipher->keylen = keylen;

  cipher->Nr = (direction == RIJNDAEL_ENCRYPT) ?
    rijndaelKeySetupEnc(cipher->rk, key, keylen) :
    rijndaelKeySetupDec(cipher->rk, key, keylen);
  rijndaelKeySetupEnc(cipher->ek, key, keylen);

  if (IV != 0)
    memcpy(cipher->IV, IV, MAX_IV_SIZE);
  else
    memset(cipher->IV, 0, MAX_IV_SIZE);
  return 1;
}
