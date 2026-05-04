#include "mlkem_native_android.h"

#include <jni.h>
#include <stdint.h>
#include <string.h>

#include "mlkem_native.h"
#include "src/indcpa.h"
#include "src/symmetric.h"
#include "src/verify.h"

#define MLKEM_NATIVE_ANDROID_KEYPAIR_OUTPUT_BYTES \
  (MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES + MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES)
#define MLKEM_NATIVE_ANDROID_ENCAPSULATION_OUTPUT_BYTES \
  (MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES + MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES)
#define MLKEM_NATIVE_ANDROID_INCREMENTAL_PART1_OUTPUT_BYTES \
  (MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES + \
   MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES + \
   MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES)

void mlkem_native_android_sha3_256(
    const uint8_t *input, uint32_t input_length,
    uint8_t digest[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES])
{
  mlk_hash_h(digest, input, input_length);
}

int mlkem_native_android_keypair_derand(
    const uint8_t seed[MLKEM_NATIVE_ANDROID_KEYPAIR_SEED_BYTES],
    uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES])
{
  return crypto_kem_keypair_derand(public_key, secret_key, seed);
}

int mlkem_native_android_encapsulate_derand(
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    const uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES],
    uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES])
{
  return crypto_kem_enc_derand(ciphertext, shared_secret, public_key, coins);
}

int mlkem_native_android_decapsulate(
    const uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES],
    const uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES])
{
  return crypto_kem_dec(shared_secret, ciphertext, secret_key);
}

int mlkem_native_android_check_public_key(
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES])
{
  return crypto_kem_check_pk(public_key);
}

int mlkem_native_android_check_secret_key(
    const uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES])
{
  return crypto_kem_check_sk(secret_key);
}

int mlkem_native_android_encapsulate_incremental_part1(
    const uint8_t header[MLKEM_NATIVE_ANDROID_INCREMENTAL_HEADER_BYTES],
    const uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES],
    uint8_t encapsulation_secret
        [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    uint8_t ciphertext_part1[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES],
    uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES])
{
  int ret;
  uint8_t hash_input[2 * MLKEM_SYMBYTES];
  uint8_t kr[2 * MLKEM_SYMBYTES];
  uint8_t public_key_for_part1[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES];
  uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES];

  mlk_memcpy(hash_input, coins, MLKEM_SYMBYTES);
  mlk_memcpy(hash_input + MLKEM_SYMBYTES, header + MLKEM_SYMBYTES,
             MLKEM_SYMBYTES);
  mlk_hash_g(kr, hash_input, sizeof(hash_input));

  memset(public_key_for_part1, 0, MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES);
  mlk_memcpy(public_key_for_part1 +
                 MLKEM_NATIVE_ANDROID_ENCAPSULATION_KEY_VECTOR_BYTES,
             header, MLKEM_SYMBYTES);

  ret = mlk_indcpa_enc(ciphertext, coins, public_key_for_part1,
                       kr + MLKEM_SYMBYTES, NULL);
  if (ret == 0) {
    mlk_memcpy(encapsulation_secret, coins, MLKEM_SYMBYTES);
    mlk_memcpy(encapsulation_secret + MLKEM_SYMBYTES, kr + MLKEM_SYMBYTES,
               MLKEM_SYMBYTES);
    mlk_memcpy(ciphertext_part1, ciphertext,
               MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES);
    mlk_memcpy(shared_secret, kr, MLKEM_SYMBYTES);
  }

  mlk_zeroize(ciphertext, sizeof(ciphertext));
  mlk_zeroize(public_key_for_part1, sizeof(public_key_for_part1));
  mlk_zeroize(kr, sizeof(kr));
  mlk_zeroize(hash_input, sizeof(hash_input));

  return ret;
}

int mlkem_native_android_encapsulate_incremental_part2(
    const uint8_t encapsulation_secret
        [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES],
    const uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES],
    uint8_t ciphertext_part2[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES])
{
  int ret = 0;
  uint8_t public_key_hash[MLKEM_SYMBYTES];
  uint8_t hash_input[2 * MLKEM_SYMBYTES];
  uint8_t expected_kr[2 * MLKEM_SYMBYTES];
  uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES];

  mlk_hash_h(public_key_hash, public_key, MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES);
  mlk_memcpy(hash_input, encapsulation_secret, MLKEM_SYMBYTES);
  mlk_memcpy(hash_input + MLKEM_SYMBYTES, public_key_hash, MLKEM_SYMBYTES);
  mlk_hash_g(expected_kr, hash_input, sizeof(hash_input));

  if (mlk_ct_memcmp(encapsulation_secret + MLKEM_SYMBYTES,
                    expected_kr + MLKEM_SYMBYTES, MLKEM_SYMBYTES) != 0) {
    ret = MLK_ERR_FAIL;
    goto cleanup;
  }

  ret = crypto_kem_enc_derand(ciphertext, shared_secret, public_key,
                              encapsulation_secret);
  if (ret != 0) {
    goto cleanup;
  }

  if (mlk_ct_memcmp(shared_secret, expected_kr, MLKEM_SYMBYTES) != 0) {
    ret = MLK_ERR_FAIL;
    goto cleanup;
  }

  mlk_memcpy(ciphertext_part2,
             ciphertext + MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES,
             MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES);

cleanup:
  mlk_zeroize(shared_secret, sizeof(shared_secret));
  mlk_zeroize(ciphertext, sizeof(ciphertext));
  mlk_zeroize(expected_kr, sizeof(expected_kr));
  mlk_zeroize(hash_input, sizeof(hash_input));
  mlk_zeroize(public_key_hash, sizeof(public_key_hash));

  return ret;
}

static int read_fixed_array(JNIEnv *env, jbyteArray source, uint8_t *destination,
                            jsize expected_length)
{
  if (source == NULL || (*env)->GetArrayLength(env, source) != expected_length) {
    return -1;
  }

  (*env)->GetByteArrayRegion(env, source, 0, expected_length,
                             (jbyte *)destination);
  return (*env)->ExceptionCheck(env) ? -1 : 0;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_keypairDerand(
    JNIEnv *env, jobject unused, jbyteArray seed_array)
{
  (void)unused;

  uint8_t seed[MLKEM_NATIVE_ANDROID_KEYPAIR_SEED_BYTES];
  uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES];
  uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES];

  if (read_fixed_array(env, seed_array, seed,
                       MLKEM_NATIVE_ANDROID_KEYPAIR_SEED_BYTES) != 0) {
    return NULL;
  }

  if (mlkem_native_android_keypair_derand(seed, public_key, secret_key) != 0) {
    return NULL;
  }

  jbyteArray output =
      (*env)->NewByteArray(env, MLKEM_NATIVE_ANDROID_KEYPAIR_OUTPUT_BYTES);
  if (output == NULL) {
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, output, 0,
                             MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES,
                             (const jbyte *)public_key);
  (*env)->SetByteArrayRegion(env, output, MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES,
                             MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES,
                             (const jbyte *)secret_key);

  return output;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_encapsulateDerand(
    JNIEnv *env, jobject unused, jbyteArray public_key_array,
    jbyteArray coins_array)
{
  (void)unused;

  uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES];
  uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES];
  uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES];
  uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES];

  if (read_fixed_array(env, public_key_array, public_key,
                       MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES) != 0 ||
      read_fixed_array(env, coins_array, coins,
                       MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES) != 0) {
    return NULL;
  }

  if (mlkem_native_android_encapsulate_derand(public_key, coins, ciphertext,
                                             shared_secret) != 0) {
    return NULL;
  }

  jbyteArray output =
      (*env)->NewByteArray(env, MLKEM_NATIVE_ANDROID_ENCAPSULATION_OUTPUT_BYTES);
  if (output == NULL) {
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, output, 0,
                             MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES,
                             (const jbyte *)ciphertext);
  (*env)->SetByteArrayRegion(env, output,
                             MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES,
                             MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES,
                             (const jbyte *)shared_secret);

  return output;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_decapsulate(
    JNIEnv *env, jobject unused, jbyteArray ciphertext_array,
    jbyteArray secret_key_array)
{
  (void)unused;

  uint8_t ciphertext[MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES];
  uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES];
  uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES];

  if (read_fixed_array(env, ciphertext_array, ciphertext,
                       MLKEM_NATIVE_ANDROID_CIPHERTEXT_BYTES) != 0 ||
      read_fixed_array(env, secret_key_array, secret_key,
                       MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES) != 0) {
    return NULL;
  }

  if (mlkem_native_android_decapsulate(ciphertext, secret_key, shared_secret) !=
      0) {
    return NULL;
  }

  jbyteArray output =
      (*env)->NewByteArray(env, MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES);
  if (output == NULL) {
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, output, 0,
                             MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES,
                             (const jbyte *)shared_secret);
  return output;
}

JNIEXPORT jboolean JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_checkPublicKey(
    JNIEnv *env, jobject unused, jbyteArray public_key_array)
{
  (void)unused;

  uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES];
  if (read_fixed_array(env, public_key_array, public_key,
                       MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES) != 0) {
    return JNI_FALSE;
  }

  return mlkem_native_android_check_public_key(public_key) == 0 ? JNI_TRUE
                                                               : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_checkSecretKey(
    JNIEnv *env, jobject unused, jbyteArray secret_key_array)
{
  (void)unused;

  uint8_t secret_key[MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES];
  if (read_fixed_array(env, secret_key_array, secret_key,
                       MLKEM_NATIVE_ANDROID_SECRET_KEY_BYTES) != 0) {
    return JNI_FALSE;
  }

  return mlkem_native_android_check_secret_key(secret_key) == 0 ? JNI_TRUE
                                                               : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_sha3256(
    JNIEnv *env, jobject unused, jbyteArray input_array)
{
  (void)unused;

  if (input_array == NULL) {
    return NULL;
  }

  jsize input_length = (*env)->GetArrayLength(env, input_array);
  jbyte *input = (*env)->GetByteArrayElements(env, input_array, NULL);
  if (input == NULL) {
    return NULL;
  }

  uint8_t digest[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES];
  mlkem_native_android_sha3_256((const uint8_t *)input, (uint32_t)input_length,
                                digest);
  (*env)->ReleaseByteArrayElements(env, input_array, input, JNI_ABORT);

  jbyteArray output =
      (*env)->NewByteArray(env, MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES);
  if (output == NULL) {
    mlk_zeroize(digest, sizeof(digest));
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, output, 0,
                             MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES,
                             (const jbyte *)digest);
  mlk_zeroize(digest, sizeof(digest));
  return output;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_incrementalEncapsulatePart1(
    JNIEnv *env, jobject unused, jbyteArray header_array, jbyteArray coins_array)
{
  (void)unused;

  uint8_t header[MLKEM_NATIVE_ANDROID_INCREMENTAL_HEADER_BYTES];
  uint8_t coins[MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES];
  uint8_t encapsulation_secret
      [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES];
  uint8_t ciphertext_part1[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES];
  uint8_t shared_secret[MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES];

  if (read_fixed_array(env, header_array, header,
                       MLKEM_NATIVE_ANDROID_INCREMENTAL_HEADER_BYTES) != 0 ||
      read_fixed_array(env, coins_array, coins,
                       MLKEM_NATIVE_ANDROID_ENCAPSULATION_SEED_BYTES) != 0) {
    return NULL;
  }

  if (mlkem_native_android_encapsulate_incremental_part1(
          header, coins, encapsulation_secret, ciphertext_part1,
          shared_secret) != 0) {
    mlk_zeroize(coins, sizeof(coins));
    return NULL;
  }

  jbyteArray output =
      (*env)->NewByteArray(env,
                           MLKEM_NATIVE_ANDROID_INCREMENTAL_PART1_OUTPUT_BYTES);
  if (output == NULL) {
    mlk_zeroize(shared_secret, sizeof(shared_secret));
    mlk_zeroize(ciphertext_part1, sizeof(ciphertext_part1));
    mlk_zeroize(encapsulation_secret, sizeof(encapsulation_secret));
    mlk_zeroize(coins, sizeof(coins));
    return NULL;
  }

  (*env)->SetByteArrayRegion(
      env, output, 0,
      MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES,
      (const jbyte *)encapsulation_secret);
  (*env)->SetByteArrayRegion(
      env, output,
      MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES,
      MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES,
      (const jbyte *)ciphertext_part1);
  (*env)->SetByteArrayRegion(
      env, output,
      MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES +
          MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART1_BYTES,
      MLKEM_NATIVE_ANDROID_SHARED_SECRET_BYTES, (const jbyte *)shared_secret);

  mlk_zeroize(shared_secret, sizeof(shared_secret));
  mlk_zeroize(ciphertext_part1, sizeof(ciphertext_part1));
  mlk_zeroize(encapsulation_secret, sizeof(encapsulation_secret));
  mlk_zeroize(coins, sizeof(coins));
  return output;
}

JNIEXPORT jbyteArray JNICALL
Java_io_github_marlonjd_mlkemnative_MLKEMNative768_00024Native_incrementalEncapsulatePart2(
    JNIEnv *env, jobject unused, jbyteArray encapsulation_secret_array,
    jbyteArray public_key_array)
{
  (void)unused;

  uint8_t encapsulation_secret
      [MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES];
  uint8_t public_key[MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES];
  uint8_t ciphertext_part2[MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES];

  if (read_fixed_array(
          env, encapsulation_secret_array, encapsulation_secret,
          MLKEM_NATIVE_ANDROID_INCREMENTAL_ENCAPSULATION_SECRET_BYTES) != 0 ||
      read_fixed_array(env, public_key_array, public_key,
                       MLKEM_NATIVE_ANDROID_PUBLIC_KEY_BYTES) != 0) {
    return NULL;
  }

  if (mlkem_native_android_encapsulate_incremental_part2(
          encapsulation_secret, public_key, ciphertext_part2) != 0) {
    mlk_zeroize(encapsulation_secret, sizeof(encapsulation_secret));
    return NULL;
  }

  jbyteArray output =
      (*env)->NewByteArray(env, MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES);
  if (output == NULL) {
    mlk_zeroize(ciphertext_part2, sizeof(ciphertext_part2));
    mlk_zeroize(encapsulation_secret, sizeof(encapsulation_secret));
    return NULL;
  }

  (*env)->SetByteArrayRegion(env, output, 0,
                             MLKEM_NATIVE_ANDROID_CIPHERTEXT_PART2_BYTES,
                             (const jbyte *)ciphertext_part2);

  mlk_zeroize(ciphertext_part2, sizeof(ciphertext_part2));
  mlk_zeroize(encapsulation_secret, sizeof(encapsulation_secret));
  return output;
}
