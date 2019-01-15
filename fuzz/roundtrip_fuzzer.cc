#include <string.h>
#include <sodium/crypto_vrf.h>
#include <sodium.h>
#include <assert.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int ret;

    ret = sodium_init();
    assert(ret >= 0);
    unsigned char pk[crypto_vrf_PUBLICKEYBYTES];
    unsigned char sk[crypto_vrf_SECRETKEYBYTES];
    unsigned char seed[crypto_vrf_SEEDBYTES] = {};
    // copy as many bytes into the seed as we can
    int seedsize = crypto_vrf_SEEDBYTES;
    if (size < crypto_vrf_SEEDBYTES) {
        seedsize = size;
    }
    memcpy(seed, data, seedsize);
    crypto_vrf_keypair_from_seed(pk, sk, seed);
    ret = crypto_vrf_is_valid_key(pk);
    if (ret != 0) {
        // invalid key.
        return 0;
    }

    unsigned char proof[crypto_vrf_PROOFBYTES];
    ret = crypto_vrf_prove(proof, sk, data, size);
    assert(ret == 0);

    unsigned char output[crypto_vrf_OUTPUTBYTES];
    ret = crypto_vrf_proof_to_hash(output, proof);
    assert(ret == 0);

    unsigned char voutput[crypto_vrf_OUTPUTBYTES];
    ret = crypto_vrf_verify(voutput, pk, proof, data, size);
    assert(ret == 0);

    assert(memcmp(voutput, output, crypto_vrf_OUTPUTBYTES) == 0);
    return 0;
}
