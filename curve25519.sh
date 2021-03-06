djb=curve25519-20050915
echo ======================
echo Building curve25519
echo Some errors are normal
echo ======================
set -e
CC="`head -n 1 conf-cc`"
export CC
rm -f curve25519-*/*.[ao]
if make -C ${djb} curve25519.a curve25519.h
then
  impl=$( head -n 1 ${djb}/curve25519.impl )
  echo ${djb}/curve25519_${impl}.h ${djb}/curve25519.a > curve25519.impl
elif ( cd curve25519-donna && ${CC} -c curve25519-donna-c64.c )
then
  ( cd curve25519-donna && ar cr curve25519-donna.a curve25519-donna-c64.o && ranlib curve25519-donna.a )
  echo curve25519-donna.h curve25519-donna/curve25519-donna.a > curve25519.impl
else
  (
    cd curve25519-donna
    ${CC} -c curve25519-donna.c
    ar cr curve25519-donna.a curve25519-donna.o
    ranlib curve25519-donna.a
  )
  echo curve25519-donna.h curve25519-donna/curve25519-donna.a > curve25519.impl
fi
