/* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#pragma once

#include "types.h"

////////////////////////////////////////////////////////////////
// Below three APIs (keygen, encaps, decaps) are defined by NIST:
////////////////////////////////////////////////////////////////
// Keygenerate - pk is the public key,
//               sk is the private key,
int crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

// Encapsulate - pk is the public key,
//               ct is a key encapsulation message (ciphertext),
//               ss is the shared secret.
int crypto_kem_enc(OUT unsigned char *     ct,
                   OUT unsigned char *     ss,
                   IN const unsigned char *pk);





// Decapsulate - ct is a key encapsulation message (ciphertext),
//               sk is the private key,
//               ss is the shared secret
int crypto_kem_dec(OUT unsigned char *     ss,
                   IN const unsigned char *ct,
                   IN const unsigned char *sk);


// my functions


int gen_faulty_key(
                 IN int error_h0,
                 IN int error_01,
                 IN Insert_Custom_Error_Function custom_error_function,
                 OUT unsigned char* error_pos_in_h0,
                 OUT unsigned char* error_pos_in_h1,
                 OUT unsigned char *pk, 
                 OUT unsigned char *sk);

int crypto_kem_enc_plus_info(OUT unsigned char *     ct,
                   OUT unsigned char *     ss,
                   IN const unsigned char *pk,
                   OUT struct Meta_Info_enc *     info);



int crypto_kem_enc_changed_e(OUT unsigned char *     ct,
                   OUT unsigned char *     ss,
                   OUT unsigned char** e_out,
                   IN const unsigned char *pk,
                   IN Change_Error_Vectors_Fun change_error_vectors_fun);
                   //IN int change_e);


int crypto_kem_dec_changed_e(OUT unsigned char *     ss,
                   OUT unsigned char** e_out,
                   IN const unsigned char *ct,
                   IN const unsigned char *sk);

