# SPHINCS-SHA256
[SPHINCS](https://sphincs.cr.yp.to/) is a post-quantum secure hash-based digital signature scheme.

This implementation is based on the original SPHINCS implementation
available in [Supercop](https://bench.cr.yp.to/supercop.html), but uses
an optimized SHA256 [implementation](https://github.com/kste/sha256_avx).

On Intel Skylake this implementation achieves the following performance:

Operation | Cycles
------------ | -------------
KeyGeneration | 8.823.584
Signing | 144.530.760
Verify | 3.301.330
