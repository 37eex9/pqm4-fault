#include "api.h"
#include "randombytes.h"
#include "hal.h"
#include "serial-com.h"

#include <string.h>

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

// reset pseudo random number generator // see randombytes.c
void randombytes_regen(void);
void rb_reset(void);

#if defined(STM32F303RCT7)
#define TRIGGER
#define LEDS
#endif

#if defined(STM32F2) || defined(STM32F4) || defined(STM32L4R5ZI) && !defined(MPS2_AN386)
void randombytes_regen(void) {}
void rb_reset(void) {}
#endif



unsigned char key_a[MUPQ_CRYPTO_BYTES], key_b[MUPQ_CRYPTO_BYTES];
unsigned char pk[MUPQ_CRYPTO_PUBLICKEYBYTES];
unsigned char ct[MUPQ_CRYPTO_CIPHERTEXTBYTES];
unsigned char sk[MUPQ_CRYPTO_SECRETKEYBYTES];


void fi_done(void) {
  // send string to show specific operation is done
  unsigned char x = '#';
  hal_send( &x,1);
}

void keypair(void)
{
#ifdef LEDS
  change_err_led(1);
  change_ok_led(1);
#endif
  MUPQ_crypto_kem_keypair(pk, sk);
#ifdef LEDS
  change_err_led(0);
#endif
  fi_done();
}

void encaps(void)
{
#ifdef LEDS
  change_err_led(1);
  change_ok_led(1);
#endif
  MUPQ_crypto_kem_enc(ct, key_b, pk);
#ifdef LEDS
  change_err_led(0);
#endif
  fi_done();
}

void decaps(void)
{
#ifdef LEDS
  change_err_led(1);
  change_ok_led(1);
#endif
  MUPQ_crypto_kem_dec(key_a, ct, sk);
#ifdef LEDS
  change_err_led(0);
#endif
  fi_done();
}

void fi_check_ss(void)
{
  unsigned int i;
  unsigned char check = 0;

  for (i=0;i<MUPQ_CRYPTO_BYTES;i++) {
    check |= key_a[i] ^ key_b[i];
  }
  serial_send_hex(&check, 1);
  fi_done();
}

void fi_read(void)
{
  unsigned char cmd, *ptr;
  int length;

  cmd = getch();
  switch (cmd) {
      case 'a':
        ptr = key_a;
        length = MUPQ_CRYPTO_BYTES;
        break;
      case 'b':
        ptr = key_b;
        length = MUPQ_CRYPTO_BYTES;
        break;
      case 'p':
        ptr = pk;
        length = MUPQ_CRYPTO_PUBLICKEYBYTES;
        break;
      case 's':
        ptr = sk;
        length = MUPQ_CRYPTO_SECRETKEYBYTES;
        break;
      case 'c':
        ptr = ct;
        length = MUPQ_CRYPTO_CIPHERTEXTBYTES;
        break;
      default:
        ptr = &cmd;
        length = 1;
  }

  serial_send_hex(ptr, length);
  fi_done();
#ifdef LEDS
  change_err_led(0);
  change_ok_led(1);
#endif
}

void fi_write(void)
{
  char cmd;
  unsigned char *ptr;
  int length;
#ifdef LEDS
  change_err_led(1);
#endif
  cmd = getch();
  switch (cmd) {
      case 'p':
        ptr = pk;
        length = MUPQ_CRYPTO_PUBLICKEYBYTES;
        break;
      case 's':
        ptr = sk;
        length = MUPQ_CRYPTO_SECRETKEYBYTES;
        break;
      case 'c':
        ptr = ct;
        length = MUPQ_CRYPTO_CIPHERTEXTBYTES;
        break;
      default:
#ifdef LEDS
        change_err_led(1);
        change_ok_led(0);
#endif
        return;
  }

  hal_receive(ptr, length);
#ifdef LEDS
  change_err_led(0);
  change_ok_led(1);
#endif
  fi_done();
}

void reset_prng(void)
{
  rb_reset();
  fi_done();
}

void send_rand(void)
{
  uint8_t buf[20];
  int len;

  len = serial_get_len();
  if (len > 20) {
    return;
  }

  randombytes(buf, len);

  serial_send_hex(buf, len);
  fi_done();
}

void fi_set_trigger(void)
{
  char h;
  size_t len;

  h = getch();
  len = serial_get_len();
  if (h == 0) {
#ifdef TRIGGER_ADV
    trigger_set_h0(len);
#endif // TRIGGER_ADV
    fi_done();
    return;
  }
  if (h == 1) {
#ifdef TRIGGER_ADV
    trigger_set_h1(len);
#endif // TRIGGER_ADV
    fi_done();
    return;
  }
}

void toggle_led(void)
{
#ifdef LEDS
  int led;

  led = getch();
  switch (led) {
    case 0:
      toggle_ok_led();
      break;
    case 1:
      toggle_err_led();
      break;
    default:
      break;
  }
#else
  getch();
#endif
  fi_done();
}

int main(void)
{
  char cmd;

  hal_setup(CLOCK_FAST);
#ifdef LEDS
	change_ok_led(1);
#endif

  while (1) {
    cmd = getch();
    switch (cmd) {
      case 'k':  // generate key pair
        keypair();
        break;
      case 'e':  // encapsulation
        encaps();
        break;
      case 'd':  //decapsulation
        decaps();
        break;
      case 'r': // read
        fi_read();
        break;
      case 'w': // write
        fi_write();
        break;
      case 'c':
        fi_check_ss();
        break;
      case 'n':
        reset_prng();
        break;
      case 'o':
        randombytes_regen();
        fi_done();
        break;
      case 'p':
        send_rand();
        break;
#ifdef TRIGGER_ADV
      case 't':
        fi_set_trigger();
      break;
#endif // TRIGGER_ADV
      case 'l':
        toggle_led();
        break;
#ifdef LEDS
      default:
        change_ok_led(0);
        change_err_led(1);
#endif
    }
  }
}
