#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <stdint.h>


#include "common.h"
#include "zkp_common.h"

/**
 *  Fiat-Shamir / Random Oracle
 */

#define FS_HALF 32      // Half of SHA512 64 bytes digest
#define PACKING_SHIFT 682 // TODO: Check

static void fiat_shamir_init_state_from_data(uint8_t state[FS_HALF], const uint8_t *data, uint64_t data_len) {
  uint8_t digest[2*FS_HALF];
  SHA512(data, data_len, digest);
  memcpy(state, digest, FS_HALF);
}

static void fiat_shamir_bytes_from_state(uint8_t *digest, uint64_t digest_len, uint8_t state[FS_HALF])
{ 
  // Initialize RH to state, so the first hash will operate on (state, data).
  uint8_t curr_digest[2*FS_HALF];
  uint64_t add_curr_digest_bytes;

  // Continue until remaining needed digest length is 0
  while (digest_len > 0)
  {  
    // hash previous (RH,data) to get new (LH, RH)
    SHA512(state, FS_HALF, curr_digest);
    memcpy(state, curr_digest + FS_HALF, FS_HALF);

    add_curr_digest_bytes = (digest_len < FS_HALF ? digest_len : FS_HALF);
    
    // collect current LH to final digest
    memcpy(digest, curr_digest, add_curr_digest_bytes);
    
    digest += add_curr_digest_bytes;
    digest_len -= add_curr_digest_bytes;
  }

  memset(curr_digest, 0, 2*FS_HALF);
}

void fiat_shamir_bytes(uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len)
{
  // Start from default (agreed upon) state of all zeros
  uint8_t fs_state[FS_HALF];
  fiat_shamir_init_state_from_data(fs_state, data, data_len);
  fiat_shamir_bytes_from_state(digest, digest_len, fs_state);
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

  uint8_t *result_bytes = calloc(num_bytes, 1);

  uint8_t fs_state[FS_HALF];
  fiat_shamir_init_state_from_data(fs_state, data, data_len);

  for (uint64_t i_res = 0; i_res < num_res; ++i_res)
  {
    BN_copy(results[i_res], range);
    
    // Get fiat_shamir scalar (from bytes) which fits in range.
    // If doesn't, get next "fresh" scalar continuing from last state.
    while (BN_cmp(results[i_res], range) != -1)
    {
      fiat_shamir_bytes_from_state(result_bytes, num_bytes, fs_state);
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

void pack_plaintexts(scalar_t packed, const scalar_t *plaintexts, uint64_t packing_size, scalar_t domain, int test_decoding) {
  scalar_t shifted = scalar_new();

  BN_set_word(packed, 0);
  for (uint64_t p = 0; p < packing_size; ++p) {

    // To allow correct unpacking later
    if (test_decoding) {
      if (BN_num_bits(plaintexts[p]) >= PACKING_SHIFT-1) {
        //BN_set_word(packed, 0);
        printf("PACKING ERROR ########################### plaintext bitlen = %d too big for packing shift %d\n", BN_num_bits(plaintexts[p]), PACKING_SHIFT);
      //break;
      }
    }

    BN_lshift(shifted, plaintexts[p], PACKING_SHIFT*p);
    BN_add(packed, packed, shifted);
  }
  scalar_free(shifted);

  // To avoid overflow errors
  if (domain) {
    if (BN_cmp(packed, domain) == 1) {
      printf("ACKING ERROR ########################### packed bitlengh = %d overflows modulus\n", BN_num_bits(packed));
      //BN_set_word(packed, 0);
    }
  }
}

void unpack_plaintexts(scalar_t *unpacked, uint64_t packing_size, const scalar_t packed_plaintext) {

  scalar_t shifted = scalar_new();
  scalar_copy(shifted, packed_plaintext);

  scalar_t exp_2 = scalar_new();
  scalar_set_power_of_2(exp_2, PACKING_SHIFT-1);

  for (uint64_t p = 0; p < packing_size; ++p) {
    BN_add(shifted, shifted, exp_2);
    BN_lshift(exp_2, exp_2, PACKING_SHIFT);
  }
  
  scalar_set_power_of_2(exp_2, PACKING_SHIFT-1);

  uint64_t curr_bit_shift = PACKING_SHIFT*(packing_size-1);

  for (uint64_t p = packing_size; p > 0; --p) {
    
    BN_rshift(unpacked[p-1], shifted, curr_bit_shift);
    BN_sub(unpacked[p-1], unpacked[p-1], exp_2);
    
    BN_mask_bits(shifted, curr_bit_shift);
    curr_bit_shift -= PACKING_SHIFT;
  }

  scalar_free(exp_2);
  scalar_free(shifted);
}
