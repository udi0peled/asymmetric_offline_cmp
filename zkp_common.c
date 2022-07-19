#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <stdint.h>

#include "zkp_common.h"

/**
 *  Fiat-Shamir / Random Oracle
 */

#define FS_HALF 32      // Half of SHA512 64 bytes digest
#define PACKING_SHIFT 682

/** 
 *  Denote hash digest as 2 equal length (FS_HALF) parts (LH, RH).
 *  Together (LH,RH,data) is curr_digest.
 *  Iteratively Hash (RH,data) to get next Hash digest (LH,RH).
 *  Concatenate LH from all iterations to combined digest, until getting at least required digest_len bytes.
 *  Initialize first RH to given state, and final RH returned at state - which allows for future calls on same data, getting new digests by continuing the final state.
 */

static void fiat_shamir_bytes_from_state(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len, uint8_t state[FS_HALF])
{ 
  // Initialize RH to state, so the first hash will operate on (state, data).
  uint8_t *curr_digest = malloc(2*FS_HALF + data_len);
  memcpy(curr_digest + FS_HALF, state, FS_HALF);
  memcpy(curr_digest + 2*FS_HALF, data, data_len);

  uint64_t add_curr_digest_bytes;

  // Continue until remaining needed digest length is 0
  while (digest_len > 0)
  {  
    // hash previous (RH,data) to get new (LH, RH)
    SHA512(curr_digest + FS_HALF, FS_HALF + data_len, curr_digest);

    add_curr_digest_bytes = (digest_len < FS_HALF ? digest_len : FS_HALF);
    
    // collect current LH to final digest
    memcpy(digest, curr_digest, add_curr_digest_bytes);
    
    digest += add_curr_digest_bytes;
    digest_len -= add_curr_digest_bytes;
  }

  // Keep last RH as state for future calls on same data
  memcpy(state, curr_digest + FS_HALF, FS_HALF);
  memset(curr_digest, 0, 2*FS_HALF + data_len);
  free(curr_digest);
}

void fiat_shamir_bytes(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len)
{
  // Start from default (agreed upon) state of all zeros
  uint8_t fs_state[FS_HALF] = {0};
  fiat_shamir_bytes_from_state(digest, digest_len, data, data_len, fs_state);
  memset(fs_state, 0, FS_HALF);
}

/** 
 *  Get num_res scalars from fiat-shamir on data.
 *  Rejection sampling each scalar until fits in given range (to get pseudo-uniform values)
 */

void fiat_shamir_scalars_in_range(scalar_t *results, uint64_t num_res, const scalar_t range, const uint8_t *data, uint64_t data_len)
{
  uint64_t num_bits = BN_num_bits(range);
  uint64_t num_bytes = BN_num_bytes(range);

  // Start from default (agreed upon) state of all zeros
  uint8_t fs_state[FS_HALF] = {0};
  uint8_t *result_bytes = calloc(num_bytes, 1);

  for (uint64_t i_res = 0; i_res < num_res; ++i_res)
  {
    BN_copy(results[i_res], range);
    
    // Get fiat_shamir scalar (from bytes) which fits in range.
    // If doesn't, get next "fresh" scalar continuing from last state.
    while (BN_cmp(results[i_res], range) != -1)
    {
      fiat_shamir_bytes_from_state(result_bytes, num_bytes, data, data_len, fs_state);
      BN_bin2bn(result_bytes, num_bytes, results[i_res]);
      // Truncate irrelevant bits (w/o biasing distribution)
      BN_mask_bits(results[i_res], num_bits);
    }
  }

  memset(fs_state, 0, FS_HALF);
  free(result_bytes);
}

/**
 *  Auxiliary Information Handling
 */

zkp_aux_info_t *zkp_aux_info_new (uint64_t init_byte_len, const void *init_bytes)
{
  zkp_aux_info_t *aux = malloc(sizeof(*aux));
  
  aux->info = calloc(init_byte_len, 1);
  aux->info_len = init_byte_len;

  if (init_bytes) memcpy(aux->info, init_bytes, init_byte_len);

  return aux;
}

void zkp_aux_info_update(zkp_aux_info_t *aux, uint64_t at_pos, const void *update_bytes, uint64_t update_byte_len)
{
  uint64_t new_len = at_pos + update_byte_len;
  
  // Extend to new length, set with zeros
  if (new_len > aux->info_len)
  {
    aux->info = realloc(aux->info, new_len);
    memset(aux->info + aux->info_len, 0x00, new_len - aux->info_len);
    aux->info_len = new_len;
  }

  if (update_bytes)
  {
    memcpy(aux->info + at_pos, update_bytes, update_byte_len);
  }
  else
  {
    // If no bytes to update, extend/truncate to new length (zero already set above if extended).
    aux->info = realloc(aux->info, new_len);
    aux->info_len = new_len;
  }
}

void zkp_aux_info_update_move(zkp_aux_info_t *aux, uint64_t *at_pos, const void *update_bytes, uint64_t update_byte_len)
{
  zkp_aux_info_update(aux, *at_pos, update_bytes, update_byte_len);
  if (update_bytes) *at_pos += update_byte_len;
}

void zkp_aux_info_free(zkp_aux_info_t *aux)
{
  if (!aux) return;
  
  free(aux->info);
  free(aux);
}

void pack_ciphertexts(scalar_t packed, const scalar_t *ciphertext, const paillier_public_key_t *pub) {
  
  BN_CTX *bn_ctx = BN_CTX_new();
  scalar_t shifted = scalar_new();

  BN_set_word(packed, 1);
  for (uint64_t i = 0; i < PACKING_SIZE; ++i) {
    BN_mod_lshift(shifted, ciphertext[i], PACKING_SHIFT*i,  pub->N2, bn_ctx);
    BN_mod_mul(packed, packed, shifted, pub->N2, bn_ctx);
  }
  BN_CTX_free(bn_ctx);
}

void pack_plaintexts(scalar_t packed, const scalar_t *plaintext, const paillier_public_key_t *pub) {
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t shifted = scalar_new();

  BN_set_word(packed, 0);
  for (uint64_t i = 0; i < PACKING_SIZE; ++i) {
    BN_mod_lshift(shifted, plaintext[i], PACKING_SHIFT*i,  pub->N, bn_ctx);
    BN_mod_add(packed, packed, shifted, pub->N, bn_ctx);
  }
  scalar_free(shifted);
  BN_CTX_free(bn_ctx);
}


scalar_t *new_scalar_array(uint64_t len) {
  scalar_t *scalars = calloc(len, sizeof(scalar_t));
  for (uint64_t i = 0; i < len; ++i) scalars[i] = scalar_new();
  return scalars;
}

gr_elem_t *new_gr_el_array(uint64_t len, ec_group_t ec) {
  gr_elem_t *grels = calloc(len, sizeof(gr_elem_t));
  for (uint64_t i = 0; i < len; ++i) grels[i] = group_elem_new(ec);
  return grels;
}

void free_scalar_array(scalar_t * scalars, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) scalar_free(scalars[i]);
  free(scalars);
}

void free_gr_el_array(gr_elem_t * grels, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) group_elem_free(grels[i]);
  free(grels);
}

void copy_scalar_array(scalar_t *copy, scalar_t *source, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) scalar_copy(copy[i], source[i]);
}

void copy_gr_el_array(gr_elem_t *copy, gr_elem_t *source, uint64_t len) {
  for (uint64_t i = 0; i < len; ++i) group_elem_copy(copy[i], source[i]);
}
