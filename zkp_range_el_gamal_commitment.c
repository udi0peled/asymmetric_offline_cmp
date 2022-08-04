#include "zkp_range_el_gamal_commitment.h"
#include "common.h"
#include <openssl/sha.h>

#define SOUNDNESS_ELL 256
#define SLACKNESS_EPS (SOUNDNESS_ELL + 64)

zkp_range_el_gamal_proof_t *zkp_range_el_gamal_new (uint64_t batch_size, uint64_t packing_size, ec_group_t ec)
{
  assert(batch_size % packing_size == 0);

  zkp_range_el_gamal_proof_t *proof = malloc(sizeof(zkp_range_el_gamal_proof_t));
  
  proof->batch_size = batch_size;
  proof->packing_size = packing_size;

  proof->V1   = gr_el_array_new(packing_size, ec);
  proof->V2   = gr_el_array_new(packing_size, ec);
  proof->z_1  = scalar_array_new(packing_size);
  proof->w    = scalar_array_new(packing_size);

  proof->packed_S = scalar_array_new(batch_size);

  proof->packed_D = scalar_new();
  proof->packed_T = scalar_new();

  proof->packed_z_2 = scalar_new();
  proof->packed_z_3 = scalar_new();

  return proof;
}

void  zkp_range_el_gamal_free   (zkp_range_el_gamal_proof_t *proof)
{
  gr_el_array_free(proof->V1, proof->packing_size);
  gr_el_array_free(proof->V2, proof->packing_size);
  scalar_array_free(proof->z_1, proof->packing_size);
  scalar_array_free(proof->w, proof->packing_size);

  scalar_array_free(proof->packed_S, proof->batch_size);

  scalar_free(proof->packed_D);
  scalar_free(proof->packed_T);
  scalar_free(proof->packed_z_2);
  scalar_free(proof->packed_z_3);

  free(proof);
}

void zkp_range_el_gamal_challenge (scalar_t *e, const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  assert(public->packing_size == proof->packing_size);
  assert(public->batch_size == proof->batch_size);

  uint64_t batch_size = proof->batch_size;
  uint64_t packing_size = proof->packing_size;
  uint64_t packed_len = batch_size / packing_size;
  
  uint64_t fs_data_len = aux->info_len + GROUP_ELEMENT_BYTES*(2 + 2*packing_size + 2*batch_size) + PAILLIER_MODULUS_BYTES*(3 + 2*packed_len) + RING_PED_MODULUS_BYTES*(3 + packing_size + packed_len);

  uint8_t *fs_data = malloc(fs_data_len);
  memset(fs_data, 0x00, fs_data_len);
  uint8_t *data_pos = fs_data;

  // memcpy(data_pos, aux->info, aux->info_len);
  // data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);

  for (uint64_t p = 0; p < packing_size; ++p) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s[p], 1);
  }

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->ec, 1);
  
  for (uint64_t i = 0; i < batch_size; ++i)
  {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->A1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->A2[i], public->ec, 1);
  }
  
  for (uint64_t i = 0; i < packed_len; ++i)
  {
    scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES,public->packed_C[i], 1);
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES,  proof->packed_S[i], 1);
  }
  
  for (uint64_t p = 0; p < packing_size; ++p) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V1[p], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V2[p], public->ec, 1);
  }

  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->packed_D, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->packed_T, 1);

  //assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, packed_len, ec_group_order(public->ec), fs_data, fs_data_len);

  for (uint64_t i = 0; i < packed_len; ++i) {
    scalar_make_signed(e[i], ec_group_order(public->ec));
  }

  free(fs_data);
}

void zkp_range_el_gamal_prove (zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_secret_t *secret, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{  
  assert(public->packing_size == proof->packing_size);
  assert(public->batch_size == proof->batch_size);

  uint64_t batch_size = proof->batch_size;
  uint64_t packing_size = proof->packing_size;
  uint64_t packed_len = batch_size / packing_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t temp_range = scalar_new();
  scalar_t temp       = scalar_new();
  scalar_t gamma      = scalar_new();
  scalar_t r          = scalar_new();
  scalar_t alpha_pack = scalar_new();
  scalar_t *mu        = scalar_array_new(packed_len);
  scalar_t *e         = scalar_array_new(packed_len);

  scalar_t *alpha = scalar_array_new(packing_size); 
  scalar_t *beta  = scalar_array_new(packing_size);

  scalar_set_power_of_2(temp_range, SOUNDNESS_ELL + SLACKNESS_EPS);

  for (uint64_t p = 0; p < packing_size; ++p) {
    scalar_sample_in_range(alpha[p], temp_range, 0, bn_ctx);
    scalar_make_signed(alpha[p], temp_range);

    scalar_sample_in_range(beta[p], ec_group_order(public->ec), 0, bn_ctx);
  }

  BN_lshift(temp_range, public->rped_pub->N, SLACKNESS_EPS);

  scalar_sample_in_range(gamma, temp_range, 0, bn_ctx);
  scalar_make_signed(gamma, temp_range);

  paillier_encryption_sample(r, public->paillier_pub);

  // Start computing anchors
  BN_lshift(temp_range, public->rped_pub->N, SOUNDNESS_ELL);

  for (uint64_t i = 0; i < packed_len; ++i) {
    scalar_sample_in_range(mu[i], temp_range, 0, bn_ctx);
    ring_pedersen_commit(proof->packed_S[i], &secret->x[packing_size*i], packing_size, mu[i], public->rped_pub);
  }

  pack_plaintexts(alpha_pack, alpha, packing_size, public->paillier_pub->N, 1);
  paillier_encryption_encrypt(proof->packed_D, alpha_pack, r, public->paillier_pub);

  for (uint64_t p = 0; p < packing_size; ++p) {
    group_operation(proof->V1[p], NULL, NULL, ec_group_generator(public->ec), beta[p], public->ec, bn_ctx);

    group_operation(proof->V2[p], NULL, NULL, ec_group_generator(public->ec), alpha[p], public->ec, bn_ctx);
    group_operation(proof->V2[p], proof->V2[p], NULL, public->Y, beta[p], public->ec, bn_ctx);
  }

  ring_pedersen_commit(proof->packed_T, alpha, packing_size, gamma, public->rped_pub);

  zkp_range_el_gamal_challenge(e, proof, public, aux);

  for (uint64_t p = 0; p < packing_size; ++p) {

    BN_copy(proof->z_1[p], alpha[p]);
    BN_copy(proof->w[p], beta[p]);

// TODO: Falty proove causes memory error and wrong error check by party

    for (uint64_t i = 0; i < packed_len; ++i) {

      BN_mul(temp, e[i], secret->x[packing_size*i + p], bn_ctx);
      BN_add(proof->z_1[p], proof->z_1[p], temp); 

      BN_mod_mul(temp, e[i], secret->b[packing_size*i + p], ec_group_order(public->ec), bn_ctx);
      BN_mod_add(proof->w[p], proof->w[p], temp,  ec_group_order(public->ec), bn_ctx);
    }
  }

  BN_copy(proof->packed_z_2, r);
  BN_copy(proof->packed_z_3, gamma);

  for (uint64_t i = 0; i < packed_len; ++i) {

    BN_mod_exp(temp, secret->rho[i], e[i], public->paillier_pub->N, bn_ctx);
    if (BN_is_negative(e[i])) BN_mod_inverse(temp, temp, public->paillier_pub->N, bn_ctx);

    BN_mod_mul(proof->packed_z_2, proof->packed_z_2, temp, public->paillier_pub->N, bn_ctx);

    BN_mul(temp, mu[i], e[i], bn_ctx);
    BN_add(proof->packed_z_3, proof->packed_z_3, temp); 
  }

  scalar_array_free(alpha, packing_size);
  scalar_array_free(beta, packing_size);

  scalar_array_free(mu, packed_len);
  scalar_array_free(e, packed_len);

  scalar_free(temp_range);
  scalar_free(temp);
  scalar_free(gamma);
  scalar_free(r);
  scalar_free(alpha_pack);

  BN_CTX_free(bn_ctx);
}

int   zkp_range_el_gamal_verify (const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = proof->batch_size;
  uint64_t packing_size = proof->packing_size;
  uint64_t packed_len = batch_size / packing_size;

  BN_CTX *bn_ctx = BN_CTX_new();

  scalar_t packed  = scalar_new();
  scalar_t temp    = scalar_new();
  scalar_t lhs     = scalar_new();
  scalar_t rhs     = scalar_new();
  gr_elem_t lhs_gr = group_elem_new(public->ec);
  gr_elem_t rhs_gr = group_elem_new(public->ec);
  scalar_t *e      = scalar_array_new(packed_len);

  zkp_range_el_gamal_challenge(e, proof, public, aux);

  int is_verified = 1;
  for (uint64_t p = 0; p < packing_size; ++p) {
    is_verified &= ( BN_num_bits(proof->z_1[p]) <= SOUNDNESS_ELL + SLACKNESS_EPS );
  }

  pack_plaintexts(packed, proof->z_1, packing_size, public->paillier_pub->N, 1);
  paillier_encryption_encrypt(lhs, packed, proof->packed_z_2, public->paillier_pub);

  BN_copy(rhs, proof->packed_D); 
  for (uint64_t i = 0; i < packed_len; ++i) {
    paillier_encryption_homomorphic(rhs, public->packed_C[i], e[i], rhs, public->paillier_pub);
  }

  is_verified &= (scalar_equal(lhs, rhs) == 1);

  for (uint64_t p = 0; p < packing_size; ++p) {

      group_operation(lhs_gr, NULL, NULL, ec_group_generator(public->ec), proof->w[p], public->ec, bn_ctx);
      
      group_elem_copy(rhs_gr, proof->V1[p]);
      for (uint64_t i = 0; i < packed_len; ++i) group_operation(rhs_gr, rhs_gr, NULL, public->A1[packing_size*i + p], e[i], public->ec, bn_ctx);
      
      is_verified &= (scalar_equal(lhs, rhs) == 1);

      group_operation(lhs_gr, NULL, NULL, ec_group_generator(public->ec), proof->z_1[p], public->ec, bn_ctx);
      group_operation(lhs_gr, lhs_gr, NULL, public->Y, proof->w[p], public->ec, bn_ctx);

      group_elem_copy(rhs_gr, proof->V2[p]);
      for (uint64_t i = 0; i < packed_len; ++i) group_operation(rhs_gr, rhs_gr, NULL, public->A2[packing_size*i + p], e[i], public->ec, bn_ctx);
      
      is_verified &= (group_elem_equal(lhs_gr, rhs_gr, public->ec) == 1);
  }

  ring_pedersen_commit(lhs, proof->z_1, packing_size, proof->packed_z_3, public->rped_pub);
  
  BN_copy(rhs, proof->packed_T);
  for (uint64_t i = 0; i < packed_len; ++i) {
    scalar_exp(temp, proof->packed_S[i], e[i], public->rped_pub->N, bn_ctx);
    BN_mod_mul(rhs, rhs, temp, public->rped_pub->N, bn_ctx);
  }
  
  is_verified &= (scalar_equal(lhs, rhs) == 1);

  scalar_free(packed);
  scalar_free(temp);
  scalar_free(lhs);
  scalar_free(rhs);
  group_elem_free(lhs_gr);
  group_elem_free(rhs_gr);
  scalar_array_free(e, packed_len);
 
  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t  zkp_range_el_gamal_proof_bytelen (uint64_t batch_size, uint64_t packing_size) {
  return 3*PAILLIER_MODULUS_BYTES + 2*RING_PED_MODULUS_BYTES + packing_size*(2*GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES + SOUNDNESS_ELL/8 + SLACKNESS_EPS/8) + SLACKNESS_EPS/8 + batch_size*RING_PED_MODULUS_BYTES;
}

