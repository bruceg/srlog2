#ifndef CURVE25519_DONNA
#define CURVE25519_DONNA

extern void curve25519_donna(unsigned char *,const unsigned char *,const unsigned char *);

#ifndef curve25519_implementation
#define curve25519_implementation "curve25519_donna"
#define curve25519 curve25519_donna
#endif

#endif
