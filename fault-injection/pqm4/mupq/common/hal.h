#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stdlib.h>

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str(const char* in);
uint64_t hal_get_time(void);
size_t hal_get_stack_size(void);
void hal_spraystack(void);
size_t hal_checkstack(void);


// additional functions for communication
// set triggers for chipwhisperer project / python api
#ifdef TRIGGER
#   ifdef TRIGGER_ADV
void trigger_set_h0(size_t h0);
void trigger_set_h1(size_t h1);
void trigger_enable_h0(void);
void trigger_enable_h1(void);
void trigger_high_adv(void);
#   endif // TRIGGER_ADV
void trigger_setup(void);
void trigger_high(void);
void trigger_low(void);
#endif

// USART communication
char getch(void);
void putch(char c);
void hal_send(uint8_t * send, uint16_t len);
void hal_receive(uint8_t * recv, uint16_t len);

#endif
