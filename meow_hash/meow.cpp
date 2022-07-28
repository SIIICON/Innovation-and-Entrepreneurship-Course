#include<iostream>

#include "meow_hash_x64_aesni.h"

using namespace std;

// Compile with: gcc -O3 -march=native partial_key_recovery.c -o partial_key_recovery
#include <stdint.h>
#include <stdio.h>
#include "meow_hash_x64_aesni.h"
#include<emmintrin.h>
#include<intrin.h>


#define DELTA 0x1d
#define DELTA_PRIME 0x09838680

// We need a PRNG to randomize bits of the message to get multiple chances at success.

static uint64_t gen_pseudorand(uint64_t use, uint64_t trial, uint64_t worker_number) {
    __m128i state = _mm_set_epi64x(use, 0x12345678);
    __m128i key = _mm_set_epi64x(trial, worker_number);
    for (int i = 0; i < 4; i++)
        state = _mm_aesdec_si128(state, key);

    return _mm_cvtsi128_si64(state);
}



static void print_num(int length, uint8_t* data) {
    for (int i = 0; i < length; i++)
        printf("%02x", data[i]);
    printf("\n");
}

void apply_vanishing_characteristic(uint8_t* msg) {
    msg[31] ^= DELTA;
    msg[159] ^= DELTA;
    msg[255] ^= DELTA;
    //assert((*(uint32_t*)(msg + 119)) == 0);
    *((uint32_t*)(msg + 168)) ^= DELTA_PRIME;
    *((uint32_t*)(msg + 215)) ^= DELTA_PRIME;
    *((uint32_t*)(msg + 264)) ^= DELTA_PRIME;
}


int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: partial_key_recovery secret_key_index worker_number\n");
        return 1;
    }
    uint64_t secret_key_index = atoi(argv[1]);
    uint64_t worker_number = atoi(argv[2]);

    // Generate a random secret key -- our only interface to this key will be hashing under it.
    uint8_t secret_key[128];
    for (int i = 0; i < 16; i++)
        ((uint64_t*)secret_key)[i] = gen_pseudorand(1, i, secret_key_index);
    printf("Secret key: "); print_num(128, secret_key);
    printf("The search should return either: 0x%02x or 0x%02x\n", secret_key[31], secret_key[31] ^ DELTA);
    fflush(stdout); // Flush so GNU parallel will print the above messages immediately.

    uint8_t deduplicated_guess_bytes[128];
    int index = 0;
    for (int b = 0; b < 256; b++) {
        for (int i = 0; i < index; i++)
            if (deduplicated_guess_bytes[i] == b ^ DELTA)
                goto skip;
        deduplicated_guess_bytes[index++] = b;
    skip:;
    }

    uint8_t message[512] = "JingruTang202000180044";
    uint8_t sdu[] = "sdu_cst_20220610";

    for (uint64_t trial = 0; ; trial++) {
  
        //*((uint64_t*)message) = gen_pseudorand(0, trial, worker_number);
        // We need to randomize over the inputs to the other two sboxes to get multiple chances.
        message[159] = message[0];
        message[255] = message[1];

        for (int guess_byte_index = 0; guess_byte_index < 128; guess_byte_index++) {
            int guess_byte = deduplicated_guess_bytes[guess_byte_index];
            message[31] = guess_byte;
            meow_u128 h1;
            for (int i = 0; i < 16; i++)
            {
                h1.m128i_u8[i] = sdu[i];
            }
            //meow_u128 h1 = MeowHash(secret_key, 512, message);
            apply_vanishing_characteristic(message);
            meow_u128 h2 = MeowHash(secret_key, 512, message);
            apply_vanishing_characteristic(message);

            if (_mm_test_all_ones(_mm_cmpeq_epi8(h1, h2))) {
                //printf("Collision: guess_byte=0x%02x trial=%lu worker_number=%lu\n", guess_byte, trial, worker_number);
                //printf("Input message: "); print_num(512, message);
                cout<<"最终得出key的值为"<<guess_byte <<guess_byte ^ DELTA;
                return 0;
            }
        }
    }
}

