#ifndef MLKEM_NATIVE_ANDROID_H
#define MLKEM_NATIVE_ANDROID_H

#include <stdint.h>

#define MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES 1184
#define MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES 1088
#define MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES 32
#define MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES 2400
#define MLKEM_NATIVE_ANDROID_KEYPAIR_SEED_BYTES 64
#define MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES 32
#define MLKEM_NATIVE_ANDROID_INCREMENTAL_HEADER_BYTES 64
#define MLKEM_NATIVE_ANDROID_ENCAPSULATION_KEY_VECTOR_BYTES 1152
#define MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES 960
#define MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES 128
#define MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES 64

void mlkem_native_android_sha3_256(const uint8_t *input, uint32_t input_length,
                                   uint8_t digest[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES]);

int mlkem_native_android_keypair_derand(
    const uint8_t seed[MLKEM_NATIVE_ANDROID_KEYPAIR_SEED_BYTES],
    uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES]);

int mlkem_native_android_encapsulate_derand(
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    const uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES],
    uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES]);

int mlkem_native_android_decapsulate(
    const uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES],
    const uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES]);

int mlkem_native_android_check_public_key(
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES]);

int mlkem_native_android_check_secret_key(
    const uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES]);

int mlkem_native_android_encapsulate_incremental_part1(
    const uint8_t header[MLKEM_NATIVE_ANDROID_INCREMENTAL_HEADER_BYTES],
    const uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES],
    uint8_t encapsulation_secret
        [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    uint8_t ciphertext_part1[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES]);

int mlkem_native_android_encapsulate_incremental_part2(
    const uint8_t encapsulation_secret
        [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    uint8_t ciphertext_part2[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES]);

#endif
