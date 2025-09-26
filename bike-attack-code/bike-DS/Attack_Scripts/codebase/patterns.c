

#include "patterns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>> CONTEXT <<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// the function pattern gets the wlists and hs that have already been filled
// and the error for h0/h1 for which the sk should be adjusted.


int is_bit_set(uint32_t num, int bit) {
    // Shift 1 to the left by the specified bit position
    uint32_t mask = 1 << bit;

    // Use bitwise AND to check if the bit is set
    return (num & mask) != 0;
}
int set_bit(uint32_t num, int bit) {
    // Shift 1 to the left by the specified bit position
    uint32_t mask = 1 << bit;

    // Use bitwise AND to check if the bit is set
    return num ^ mask;
}

int count_h(uint8_t* h){
  int ret = 0;
  for (size_t i = 0; i < R_BYTES; i++){
    for (int j = 0; j < 8; j++){
      if(is_bit_set(h[i],j)) ret++;
    }    
  }
  return ret;
}

int count_bits(uint8_t* h, int length){
  int ret = 0;
  for (size_t i = 0; i < length; i++){
    for (int j = 0; j < 8; j++){
      if(is_bit_set(h[i],j)) ret++;
    }    
  }
  return ret;
}

// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>> Patterns <<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


// Fault pattern 1
void pattern_1(idx_t wlist0[D], idx_t wlist1[D], uint8_t h0[R_BYTES], uint8_t h1[R_BYTES], int err_h0, int err_h1)
{
  // do something here
  
}

// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>> Interface  <<<<<<<<<<<<<<<<<<<<<<<<<<
// >>>>>>>>>>>>>>>>>>>>>>><<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// return 1 if for the seclected err there is a key to create
// return 0 if there is not and this one should be skiped
int get_pattern(char* patter_inp, int err0, int err1, struct custom_values* infos, Insert_Custom_Error_Function* fun_ptr){

    if(strcmp(patter_inp, "pattern1") == 0){
        if(err0 < 0 || err1 < 0) return 0;
        *fun_ptr = pattern_1;
        return 1;
    }
    else{
        printf("provided pattern not found -> Abort\n");
        // avalible patterns?
    }
    
    return 1;
}












