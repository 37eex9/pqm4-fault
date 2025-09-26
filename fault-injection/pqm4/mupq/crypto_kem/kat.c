#include "api.h"
#include "hal.h"
#include "serial-com.h"
#include "nistkatrng.h"

#include <string.h>

#define NTESTS 100

// https://stackoverflow.com/a/1489985/1711232
#define PASTER(x, y) x##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(MUPQ_NAMESPACE, fun)

// use different names so we can have empty namespaces
#define MUPQ_CRYPTO_BYTES           NAMESPACE(CRYPTO_BYTES)
#define MUPQ_CRYPTO_PUBLICKEYBYTES  NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define MUPQ_CRYPTO_SECRETKEYBYTES  NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define MUPQ_CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)
#define MUPQ_CRYPTO_ALGNAME NAMESPACE(CRYPTO_ALGNAME)

#define MUPQ_crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define MUPQ_crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define MUPQ_crypto_kem_dec NAMESPACE(crypto_kem_dec)


void kat_done(void) {
  // send string to show specific operation is done
  unsigned char x = '#';
  hal_send( &x,1);
}

void kat_start(void) {
  // send string to show transmission starts
  unsigned char x = '$';
  hal_send( &x,1);
}

void kat_sync_send(uint8_t *ptr, uint16_t length)
{
  // kat_start();
  serial_send_hex(ptr, length);
  kat_done();
}

void kat_nxt_cnt(void) {
  // send string to to mark new iteration
  unsigned char x = '=';
  hal_send( &x,1);
}

void randombytes_reset(void)
{
  unsigned char entropy_input[48];

  for (int i=0; i<48; i++) {
    entropy_input[i] = i;
  }

  nist_kat_init(entropy_input, NULL, 256);
}


int main(void)
{
  unsigned char       seed[48];
  unsigned char       ct[MUPQ_CRYPTO_CIPHERTEXTBYTES], ss[MUPQ_CRYPTO_BYTES], ss1[MUPQ_CRYPTO_BYTES];
  unsigned char       pk[MUPQ_CRYPTO_PUBLICKEYBYTES], sk[MUPQ_CRYPTO_SECRETKEYBYTES];

  hal_setup(CLOCK_FAST);
  for (uint8_t i=0; i<NTESTS; i++) {
    kat_nxt_cnt();
    kat_sync_send(&i, 1);
   
    randombytes_reset();
    // generate seed for round i
    for (int j=0; j<=i; j++) {
        PQCLEAN_randombytes(seed, 48);
    }

    kat_sync_send(seed, 48);
    nist_kat_init(seed, NULL, 256);

    MUPQ_crypto_kem_keypair(pk, sk);
    kat_sync_send(pk, MUPQ_CRYPTO_PUBLICKEYBYTES);
    kat_sync_send(sk, MUPQ_CRYPTO_SECRETKEYBYTES);
   
    MUPQ_crypto_kem_enc(ct, ss, pk);
    kat_sync_send(ct, MUPQ_CRYPTO_CIPHERTEXTBYTES);
    kat_sync_send(ss, MUPQ_CRYPTO_BYTES);

    MUPQ_crypto_kem_dec(ss1, ct, sk);
    kat_sync_send(ss1, MUPQ_CRYPTO_BYTES);
  }

  hal_send_str("#");
  return 0;
}
