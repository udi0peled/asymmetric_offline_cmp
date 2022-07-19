#include "zkp_ring_pedersen_param.h"
#include <openssl/sha.h>

zkp_ring_pedersen_param_proof_t *zkp_ring_pedersen_param_new ()
{
  zkp_ring_pedersen_param_proof_t *proof = malloc(sizeof(zkp_ring_pedersen_param_proof_t));

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    //proof->A[i] = scalar_new();
    proof->z[i] = scalar_new();
  }

  return proof;
}

void zkp_ring_pedersen_param_free (zkp_ring_pedersen_param_proof_t *proof)
{
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    //scalar_free(proof->A[i]);
    scalar_free(proof->z[i]);
  }

  free(proof);
}

void  zkp_ring_pedersen_param_challenge (uint8_t e[STATISTICAL_SECURITY*RING_PEDERSEN_MULTIPLICITY], const zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on (N modulus, s, t, all A).

  //uint64_t fs_data_len = aux->info_len + (STATISTICAL_SECURITY + 3) * RING_PED_MODULUS_BYTES;
  uint64_t fs_data_len = aux->info_len + (2 + RING_PEDERSEN_MULTIPLICITY) * RING_PED_MODULUS_BYTES + sizeof(proof->A_hashed);
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);       data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->t, 1);
  for (uint64_t i = 0; i < RING_PEDERSEN_MULTIPLICITY; ++i) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->s[i], 1); 
  }
  
  memcpy(data_pos, proof->A_hashed, sizeof(proof->A_hashed)); data_pos += sizeof(proof->A_hashed);
  // for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i) {
  //   scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->A[i], 1);
  // }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_bytes(e, STATISTICAL_SECURITY*RING_PEDERSEN_MULTIPLICITY, fs_data, fs_data_len);

  free(fs_data);
}

void  zkp_ring_pedersen_param_prove (zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_private_t *private, const zkp_aux_info_t *aux)
{
  assert(BN_num_bytes(private->N) == RING_PED_MODULUS_BYTES);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t curr_A = scalar_new();
  uint8_t *curr_A_bytes = malloc(RING_PED_MODULUS_BYTES);

  SHA512_CTX A_hash_ctx;
  SHA512_Init(&A_hash_ctx);
  
  // Sample initial a_i as z_i (and computie commitment A[i]), so later will just add e_i*lam for final z_i.

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    scalar_sample_in_range(proof->z[i], private->phi_N, 0);
    BN_mod_exp(curr_A, private->t, proof->z[i], private->N, bn_ctx);
    scalar_to_bytes(&curr_A_bytes, RING_PED_MODULUS_BYTES, curr_A, 0);
    SHA512_Update(&A_hash_ctx, curr_A_bytes, RING_PED_MODULUS_BYTES);

    //BN_mod_exp(proof->A[i], private->t, proof->z[i], private->N, bn_ctx);
  }
  SHA512_Final(proof->A_hashed, &A_hash_ctx);

  ring_pedersen_public_t *public = ring_pedersen_public_new();
  ring_pedersen_copy_param(NULL, public, private,  NULL);

  uint8_t e[STATISTICAL_SECURITY*RING_PEDERSEN_MULTIPLICITY];     // coin flips (by LSB of each uint8_t)
  zkp_ring_pedersen_param_challenge(e, proof, public, aux);

  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    for (uint64_t j = 0; j < RING_PEDERSEN_MULTIPLICITY; ++j) {
      if (e[i*RING_PEDERSEN_MULTIPLICITY + j] & 0x01) BN_mod_add(proof->z[i], proof->z[i], private->lam[j], private->phi_N, bn_ctx);
    }
  }

  ring_pedersen_free_param(NULL, public);
  free(curr_A_bytes);
  scalar_free(curr_A);
  BN_CTX_free(bn_ctx);
}

int zkp_ring_pedersen_param_verify (const zkp_ring_pedersen_param_proof_t *proof, const ring_pedersen_public_t *public, const zkp_aux_info_t *aux)
{
  uint8_t e[STATISTICAL_SECURITY*RING_PEDERSEN_MULTIPLICITY];
  zkp_ring_pedersen_param_challenge(e, proof, public, aux);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t s_inv[RING_PEDERSEN_MULTIPLICITY];
  for (uint64_t j = 0; j < RING_PEDERSEN_MULTIPLICITY; ++j) {
    s_inv[j] = scalar_new();
    BN_mod_inverse(s_inv[j], public->s[j], public->N, bn_ctx);
  }

  scalar_t curr_A = scalar_new();
  uint8_t *curr_A_bytes = malloc(RING_PED_MODULUS_BYTES);
  
  hash_chunk computed_A_hash;
  SHA512_CTX A_hash_ctx;  

  SHA512_Init(&A_hash_ctx);
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    BN_mod_exp(curr_A, public->t, proof->z[i], public->N, bn_ctx);
    for (uint64_t j = 0; j < RING_PEDERSEN_MULTIPLICITY; ++j) {
      if (e[i*RING_PEDERSEN_MULTIPLICITY + j] & 0x01) BN_mod_mul(curr_A, curr_A, s_inv[j], public->N, bn_ctx);
    }
    scalar_to_bytes(&curr_A_bytes, RING_PED_MODULUS_BYTES, curr_A, 0);
    SHA512_Update(&A_hash_ctx, curr_A_bytes, RING_PED_MODULUS_BYTES);
  }
  SHA512_Final(computed_A_hash, &A_hash_ctx);

  int is_verified = memcmp(computed_A_hash, proof->A_hashed, sizeof(computed_A_hash)) == 0;

  scalar_free(curr_A);
  free(curr_A_bytes);
  for (uint64_t j = 0; j < RING_PEDERSEN_MULTIPLICITY; ++j) scalar_free(s_inv[j]);
  BN_CTX_free(bn_ctx);

  return is_verified;
}


uint64_t zkp_ring_pedersen_param_proof_bytelen() {
  return RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY + sizeof(hash_chunk);  // sizeof(A_hashed) = 64
}

/*

void zkp_ring_pedersen_param_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_ring_pedersen_param_proof_t *proof, int move_to_end)
{
  uint64_t needed_byte_len = RING_PED_MODULUS_BYTES*STATISTICAL_SECURITY + sizeof(proof->A_hashed);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    //scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->A[i], 1);
    memcpy(set_bytes, proof->A_hashed, sizeof(proof->A_hashed));          set_bytes += sizeof(proof->A_hashed);
    scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, proof->z[i], 1);
  }

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void zkp_ring_pedersen_param_proof_from_bytes (zkp_ring_pedersen_param_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, int move_to_end)
{
  uint64_t needed_byte_len;
  zkp_ring_pedersen_param_proof_to_bytes(NULL, &needed_byte_len, NULL, 0);

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *read_bytes = *bytes;
  
  for (uint64_t i = 0; i < STATISTICAL_SECURITY; ++i)
  {
    //scalar_from_bytes(proof->A[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
    memcpy(proof->A_hashed, read_bytes, sizeof(proof->A_hashed));     read_bytes += sizeof(proof->A_hashed);
    scalar_from_bytes(proof->z[i], &read_bytes, RING_PED_MODULUS_BYTES, 1);
  }

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}

*/