#include "zkp_range_el_gamal_commitment.h"
#include "common.h"
#include <openssl/sha.h>

#define SOUNDNESS_L 256
#define SLACKNESS_EPS (SOUNDNESS_L + 64)

zkp_range_el_gamal_proof_t *zkp_range_el_gamal_new (uint64_t batch_size, ec_group_t ec)
{
  zkp_range_el_gamal_proof_t *proof = malloc(sizeof(zkp_range_el_gamal_proof_t));
  
  proof->batch_size = batch_size;

  new_gr_el_pack(proof->V1, ec);
  new_gr_el_pack(proof->V2, ec);
  new_scalar_pack(proof->z_1);
  new_scalar_pack(proof->w);

  proof->S = new_scalar_array(batch_size);

  proof->D = scalar_new();
  proof->T = scalar_new();

  proof->z_2 = scalar_new();
  proof->z_3 = scalar_new();

  return proof;
}

void  zkp_range_el_gamal_free   (zkp_range_el_gamal_proof_t *proof)
{
  free_gr_el_pack(proof->V1);
  free_gr_el_pack(proof->V2);
  free_scalar_pack(proof->z_1);
  free_scalar_pack(proof->w);

  free_scalar_array(proof->S, proof->batch_size);
  scalar_free(proof->D);
  scalar_free(proof->T);
  scalar_free(proof->z_2);
  scalar_free(proof->z_3);

  free(proof);
}

void zkp_range_el_gamal_challenge (scalar_t *e, const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + GROUP_ELEMENT_BYTES*(2 + 2*PACKING_SIZE + 2*PACKING_SIZE*public->batch_size) + PAILLIER_MODULUS_BYTES*(3 + 2*public->batch_size) + RING_PED_MODULUS_BYTES*(2 + PACKING_SIZE + public->batch_size);

  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s[p], 1);
  }
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->G, 1);
  
  for (uint64_t i = 0; i < public->batch_size; ++i)
  {
    for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->A1[i][p], public->G, 1);
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->A2[i][p], public->G, 1);
    }
    scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES,public->C[i], 1);
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES,  proof->S[i], 1);
  }
  
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V1[p], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V2[p], public->G, 1);
  }

  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->D, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, public->batch_size, ec_group_order(public->G), fs_data, fs_data_len);

  for (uint64_t i = 0; i < public->batch_size; ++i) {
    scalar_make_signed(e[i], ec_group_order(public->G));
  }

  free(fs_data);
}

void zkp_range_el_gamal_prove (zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_secret_t *secret, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t temp_range = scalar_new();
  scalar_t temp       = scalar_new();
  scalar_t gamma      = scalar_new();
  scalar_t r          = scalar_new();
  scalar_t alpha_pack = scalar_new();
  scalar_t *mu        = new_scalar_array(public->batch_size);
  scalar_t *e         = new_scalar_array(public->batch_size);

  scalar_pack_t alpha; 
  scalar_pack_t beta;

  new_scalar_pack(alpha);
  new_scalar_pack(beta);

  scalar_set_power_of_2(temp_range, SOUNDNESS_L + SLACKNESS_EPS);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    scalar_sample_in_range(alpha[p], temp_range, 0);
    scalar_make_signed(alpha[p], temp_range);
  }

  BN_lshift(temp_range, public->rped_pub->N, SLACKNESS_EPS);

  scalar_sample_in_range(gamma, temp_range, 0);
  scalar_make_signed(gamma, temp_range);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) scalar_sample_in_range(beta[p], ec_group_order(public->G), 0);

  paillier_encryption_sample(r, public->paillier_pub);

  // Start computing anchors
  BN_lshift(temp_range, public->rped_pub->N, SOUNDNESS_L);

  for (uint64_t i = 0; i < public->batch_size; ++i) {
    scalar_sample_in_range(mu[i], temp_range, 0);
    ring_pedersen_commit(proof->S[i], secret->x[i], 3, mu[i], public->rped_pub);
  }

  pack_plaintexts(alpha_pack, alpha, public->paillier_pub);
  paillier_encryption_encrypt(proof->D, alpha_pack, r, public->paillier_pub);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    group_operation(proof->V1[p], NULL, public->g, beta[p], public->G);

    group_operation(proof->V2[p], NULL, public->g, alpha[p], public->G);
    group_operation(proof->V2[p], proof->V2[p], public->Y, beta[p], public->G);
  }

  ring_pedersen_commit(proof->T, alpha, PACKING_SIZE, gamma, public->rped_pub);

  zkp_range_el_gamal_challenge(e, proof, public, aux);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    BN_copy(proof->z_1[p], alpha[p]);
    BN_copy(proof->w[p], beta[p]);

    for (uint64_t i = 0; i < public->batch_size; ++i) {

      BN_mul(temp, e[i], secret->x[i][p], bn_ctx);
      BN_add(proof->z_1[p], proof->z_1[p], temp); 

      BN_mod_mul(temp, e[i], secret->b[i][p], ec_group_order(public->G), bn_ctx);
      BN_mod_add(proof->w[p], proof->w[p], temp,  ec_group_order(public->G), bn_ctx);
    }
  }

  BN_copy(proof->z_2, r);
  BN_copy(proof->z_3, gamma);

  for (uint64_t i = 0; i < public->batch_size; ++i) {

    scalar_exp(temp, secret->rho[i], e[i], public->paillier_pub->N);
    BN_mod_mul(proof->z_2, proof->z_2, temp, public->paillier_pub->N, bn_ctx);

    BN_mul(temp, mu[i], e[i], bn_ctx);
    BN_add(proof->z_3, proof->z_3, temp); 
  }

  free_scalar_pack(alpha);
  free_scalar_pack(beta);
  free_scalar_array(mu, public->batch_size);
  free_scalar_array(e, public->batch_size);

  scalar_free(temp_range);
  scalar_free(temp);
  scalar_free(gamma);
  scalar_free(r);
  scalar_free(alpha_pack);

  BN_CTX_free(bn_ctx);
}

int   zkp_range_el_gamal_verify (const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_new();

  scalar_t packed  = scalar_new();
  scalar_t temp    = scalar_new();
  scalar_t lhs     = scalar_new();
  scalar_t rhs     = scalar_new();
  gr_elem_t lhs_gr = group_elem_new(public->G);
  gr_elem_t rhs_gr = group_elem_new(public->G);
  scalar_t *e      = new_scalar_array(public->batch_size);

  zkp_range_el_gamal_challenge(e, proof, public, aux);

  scalar_set_power_of_2(rhs, SOUNDNESS_L + SLACKNESS_EPS);
  
  int is_verified = 1;
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    is_verified &= (BN_ucmp(proof->z_1[p], rhs) < 0);
  }

  pack_plaintexts(packed, proof->z_1, public->paillier_pub);
  paillier_encryption_encrypt(lhs, packed, proof->z_2, public->paillier_pub);

  BN_copy(rhs, proof->D); 
  for (uint64_t i = 0; i < public->batch_size; ++i) {
    scalar_exp(temp, public->C[i], e[i], public->paillier_pub->N2);
    BN_mod_mul(rhs, rhs, temp, public->paillier_pub->N2, bn_ctx);
  }

  is_verified &= (scalar_equal(lhs, rhs) == 1);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

      group_operation(lhs_gr, NULL, public->g, proof->w[p], public->G);
      
      group_elem_copy(rhs_gr, proof->V1[p]);
      for (uint64_t i = 0; i < public->batch_size; ++i) group_operation(rhs_gr, rhs_gr, public->A1[i][p], e[i], public->G);
      
      is_verified &= (scalar_equal(lhs, rhs) == 1);

      group_operation(lhs_gr, NULL, public->g, proof->z_1[p], public->G);
      group_operation(lhs_gr, lhs_gr, public->Y, proof->w[p], public->G);

      group_elem_copy(rhs_gr, proof->V2[p]);
      for (uint64_t i = 0; i < public->batch_size; ++i) group_operation(rhs_gr, rhs_gr, public->A2[i][p], e[i], public->G);
      
      is_verified &= (group_elem_equal(lhs_gr, rhs_gr, public->G) == 1);
  }

  ring_pedersen_commit(lhs, proof->z_1, PACKING_SIZE, proof->z_3, public->rped_pub);
  
  BN_copy(rhs, proof->T);
  for (uint64_t i = 0; i < public->batch_size; ++i) {
    scalar_exp(temp, proof->S[i], e[i], public->rped_pub->N);
    BN_mod_mul(rhs, rhs, temp, public->rped_pub->N, bn_ctx);
  }
  
  is_verified &= (scalar_equal(lhs, rhs) == 1);

  scalar_free(packed);
  scalar_free(temp);
  scalar_free(lhs);
  scalar_free(rhs);
  group_elem_free(lhs_gr);
  group_elem_free(rhs_gr);
  free_scalar_array(e, public->batch_size);
 
  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t  zkp_range_el_gamal_proof_bytelen (uint64_t batch_size) {
  return 3*PAILLIER_MODULUS_BYTES + 2*RING_PED_MODULUS_BYTES + 3*PACKING_SIZE*GROUP_ELEMENT_BYTES + SOUNDNESS_L/8 + 2*SLACKNESS_EPS/8 + batch_size*RING_PED_MODULUS_BYTES;
}

