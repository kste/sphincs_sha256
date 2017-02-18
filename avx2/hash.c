#include "params.h"
#include "immintrin.h"
#include "sha256.h"
#include "sha256avx.h"

#include <string.h>
#include <stddef.h>
#include <openssl/sha.h>

int varlen_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  SHA256(in,inlen,out);
  return 0;
}

int msg_hash(unsigned char *out,const unsigned char *in,unsigned long long inlen)
{
  SHA512(in,inlen,out);
  return 0;
}


static const char *hashc = "expand 32-byte to 64-byte state!";

int hash_2n_n(unsigned char *out,const unsigned char *in)
{
#if HASH_BYTES != 32
#error "Current code only supports 32-byte hashes"
#endif

  unsigned char x[64];
  int i;
  for(i=0;i<64;i++)
  {
    x[i] = in[i];
  }
  sha256(out,x);

  return 0;
}

int hash_2n_n_mask(unsigned char *out,const unsigned char *in, const unsigned char *mask)
{
  unsigned char buf[2*HASH_BYTES];
  int i;
  for(i=0;i<2*HASH_BYTES;i++)
    buf[i] = in[i] ^ mask[i];
  return hash_2n_n(out, buf);
}

int hash_n_n(unsigned char *out,const unsigned char *in)
{
#if HASH_BYTES != 32
#error "Current code only supports 32-byte hashes"
#endif
  // Have to pad with 0 for full SHA-256 block
  unsigned char x[64];
  int i;

  memset(x, 0, 64);
  memcpy(x, in, 32);

  sha256(out,x);
  return 0;
}

int hash_n_n_mask(unsigned char *out,const unsigned char *in, const unsigned char *mask)
{
  unsigned char buf[HASH_BYTES];
  int i;
  for(i=0;i<HASH_BYTES;i++)
    buf[i] = in[i] ^ mask[i];
  return hash_n_n(out, buf);
}

int hash_n_n_8x(unsigned char *out,const unsigned char *in)
{
  unsigned char x[64*8];

  // Have to pad with 0 for full SHA-256 block
  memset(x, 0, 64*8);

  int i;
  for(i=0;i<8;i++)
  {
    _mm256_storeu_si256((u256*)(x + 64*i), _mm256_loadu_si256((u256*)(in + 32*i)));
  }

  sha256_8x(out, x);
}

int hash_n_n_mask_8x(unsigned char *out,const unsigned char *in,
                     const unsigned char *mask)
{
  unsigned char x[64*8];
  int i;

  // Have to pad with zeroes for SHA256
  memset(x, 0, 64*8);

  __m256i fullmask = _mm256_loadu_si256((u256*)mask);

  for(i=0;i<8;i++)
  {
    _mm256_store_si256((u256*)(x + 64*i), _mm256_xor_si256(_mm256_load_si256((u256*)(in + 32*i)), fullmask));
  }

  sha256_8x(out, x);
}

int hash_2n_n_8x(unsigned char *out,const unsigned char *in,
      unsigned long long out_dist, unsigned long long in_dist)
{
  sha256_8x(out, in);
}

int hash_2n_n_mask_8x(unsigned char *out,const unsigned char *in,
      unsigned long long out_dist, unsigned long long in_dist,
      const unsigned char *mask)
{
  unsigned char x[in_dist*8];
  int i;

  __m256i mask_a = _mm256_loadu_si256((u256*)(mask));
  __m256i mask_b = _mm256_loadu_si256((u256*)(mask + 32));

  for(i=0;i<8;i++)
  {
    _mm256_storeu_si256((u256*)(x + 64*i), _mm256_xor_si256(_mm256_loadu_si256((u256*)(in + 64*i)), mask_a));
    _mm256_storeu_si256((u256*)(x + 64*i + 32), _mm256_xor_si256(_mm256_loadu_si256((u256*)(in + 64*i + 32)), mask_b));
  }

  sha256_8x(out, x);
}

int loop_hash_2n_n_mask_8x(unsigned char *out,const unsigned char *in,
                           unsigned long loops, const unsigned char *mask)
{
  int j;
  for(j=0;j<8*loops;j+=8)
    hash_2n_n_mask_8x(out+(j)*HASH_BYTES, in+(2*j)*HASH_BYTES,
                      HASH_BYTES, 2*HASH_BYTES, mask);
}
