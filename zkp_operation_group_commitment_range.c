#include "zkp_operation_group_commitment_range.h"

zkp_oper_group_commit_range_proof_t *zkp_oper_group_commit_range_new(const ec_group_t G)
{
  zkp_oper_group_commit_range_proof_t *proof = malloc(sizeof(zkp_oper_group_commit_range_proof_t));

  proof->B_x  = group_elem_new(G);
  proof->B_y  = scalar_new();
  proof->A    = scalar_new();
  proof->E    = scalar_new();
  proof->F    = scalar_new();
  proof->S    = scalar_new();
  proof->T    = scalar_new();
  proof->z_1  = scalar_new();
  proof->z_2  = scalar_new();
  proof->z_3  = scalar_new();
  proof->z_4  = scalar_new();
  proof->w    = scalar_new();
  proof->w_y  = scalar_new();

  return proof;
}

void  zkp_oper_group_commit_range_free   (zkp_oper_group_commit_range_proof_t *proof)
{
  group_elem_free(proof->B_x);
  scalar_free(proof->B_y);
  scalar_free(proof->A);
  scalar_free(proof->E);
  scalar_free(proof->F);
  scalar_free(proof->S);
  scalar_free(proof->T);
  scalar_free(proof->z_1);
  scalar_free(proof->z_2);
  scalar_free(proof->z_3);
  scalar_free(proof->z_4);
  scalar_free(proof->w);
  scalar_free(proof->w_y);

  free(proof);
}

void zkp_oper_group_commit_range_challenge (scalar_t e, const zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N_0 paillier_N_1, rped_N_s_t, g, C, D, Y, X, A, B_x, B_y, E, F, S, T

  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES + 12*PAILLIER_MODULUS_BYTES + 7*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub_0->N, 1);
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub_1->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s[0], 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->C, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->Y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->D, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->B_x, public->G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->B_y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->E, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->F, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->S, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->T, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(public->G), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(public->G));

  free(fs_data);
}


void zkp_oper_group_commit_range_prove (zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_secret_t *secret, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  assert((unsigned) BN_num_bytes(secret->x) <= public->x_range_bytes);
  assert((unsigned) BN_num_bytes(secret->y) <= public->y_range_bytes);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t alpha_range = scalar_new();
  scalar_t beta_range  = scalar_new();
  scalar_t gamma_range = scalar_new();    // Also delta range
  scalar_t mu_range    = scalar_new();    // Also m range
  scalar_t alpha       = scalar_new();
  scalar_t beta        = scalar_new();
  scalar_t gamma       = scalar_new();
  scalar_t delta       = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t m           = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t r_y         = scalar_new();
  scalar_t e           = scalar_new();
  scalar_t temp        = scalar_new();

  BN_set_bit(alpha_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0, bn_ctx);
  scalar_make_signed(alpha, alpha_range);

  BN_set_bit(beta_range, 8*public->y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(beta, beta_range, 0, bn_ctx);
  scalar_make_signed(beta, beta_range);

  BN_set_bit(gamma_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0, bn_ctx);
  scalar_make_signed(gamma, gamma_range);
  scalar_sample_in_range(delta, gamma_range, 0, bn_ctx);
  scalar_make_signed(delta, gamma_range);
  
  BN_set_bit(mu_range, 8*public->x_range_bytes);
  BN_mul(mu_range, mu_range, public->rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0, bn_ctx);
  scalar_make_signed(mu, mu_range);
  scalar_sample_in_range(m, mu_range, 0, bn_ctx);
  scalar_make_signed(m, mu_range);
  
  group_operation(proof->B_x, NULL, NULL, public->g, alpha, public->G, bn_ctx);

  paillier_encryption_sample(r_y, public->paillier_pub_1);
  paillier_encryption_encrypt(proof->B_y, beta, r_y, public->paillier_pub_1);

  paillier_encryption_sample(r, public->paillier_pub_0);
  paillier_encryption_encrypt(temp, beta, r, public->paillier_pub_0);
  scalar_exp(proof->A, public->C, alpha, public->paillier_pub_0->N2, bn_ctx);
  scalar_mul(proof->A, proof->A, temp, public->paillier_pub_0->N2, bn_ctx);

  ring_pedersen_commit(proof->E, &alpha, 1, gamma, public->rped_pub);
  ring_pedersen_commit(proof->F, &beta, 1, delta, public->rped_pub);
  ring_pedersen_commit(proof->S, &secret->x, 1, m, public->rped_pub);
  ring_pedersen_commit(proof->T, &secret->y, 1, mu, public->rped_pub);

  zkp_oper_group_commit_range_challenge(e, proof, public, aux);
  
  BN_mul(temp, e, secret->x, bn_ctx);
  BN_add(proof->z_1, alpha, temp);

  BN_mul(temp, e, secret->y, bn_ctx);
  BN_add(proof->z_2, beta, temp);

  BN_mul(temp, e, m, bn_ctx);
  BN_add(proof->z_3, gamma, temp);

  BN_mul(temp, e, mu, bn_ctx);
  BN_add(proof->z_4, delta, temp);

  scalar_exp(temp, secret->rho, e, public->paillier_pub_0->N, bn_ctx);
  scalar_mul(proof->w, r, temp, public->paillier_pub_0->N, bn_ctx);

  scalar_exp(temp, secret->rho_y, e, public->paillier_pub_1->N, bn_ctx);
  scalar_mul(proof->w_y, r_y, temp, public->paillier_pub_1->N, bn_ctx);

  scalar_free(temp);
  scalar_free(e);
  scalar_free(r_y);
  scalar_free(r);
  scalar_free(m);
  scalar_free(mu);
  scalar_free(delta);
  scalar_free(gamma);
  scalar_free(beta);
  scalar_free(alpha);
  scalar_free(mu_range);
  scalar_free(gamma_range);
  scalar_free(beta_range);
  scalar_free(alpha_range);

  BN_CTX_free(bn_ctx);
}

int zkp_oper_group_commit_range_verify  (const zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t z_1_range = scalar_new();
  scalar_t z_2_range = scalar_new();
  BN_set_bit(z_1_range, 8*public->x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);          // -1 since comparing signed range
  BN_set_bit(z_2_range, 8*public->y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);

  int is_verified = (BN_ucmp(proof->z_1, z_1_range) < 0) && (BN_ucmp(proof->z_2, z_2_range) < 0);

  scalar_t e = scalar_new();
  zkp_oper_group_commit_range_challenge(e, proof, public, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp = scalar_new();

  paillier_encryption_encrypt(lhs_value, proof->z_2, proof->w_y, public->paillier_pub_1);
  scalar_exp(temp, public->Y, e, public->paillier_pub_1->N2, bn_ctx);
  scalar_mul(rhs_value, proof->B_y, temp, public->paillier_pub_1->N2, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  paillier_encryption_encrypt(temp, proof->z_2, proof->w, public->paillier_pub_0);
  scalar_exp(lhs_value, public->C, proof->z_1, public->paillier_pub_0->N2, bn_ctx);
  scalar_mul(lhs_value, lhs_value, temp, public->paillier_pub_0->N2, bn_ctx);
  scalar_exp(temp, public->D, e, public->paillier_pub_0->N2, bn_ctx);
  scalar_mul(rhs_value, proof->A, temp, public->paillier_pub_0->N2, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, &proof->z_1, 1, proof->z_3, public->rped_pub);
  scalar_exp(temp, proof->S, e, public->rped_pub->N, bn_ctx);
  scalar_mul(rhs_value, proof->E, temp, public->rped_pub->N, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, &proof->z_2, 1, proof->z_4, public->rped_pub);
  scalar_exp(temp, proof->T, e, public->rped_pub->N, bn_ctx);
  scalar_mul(rhs_value, proof->F, temp, public->rped_pub->N, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  gr_elem_t lhs_gr_elem = group_elem_new(public->G);
  gr_elem_t rhs_gr_elem = group_elem_new(public->G);

  group_operation(lhs_gr_elem, NULL, NULL, public->g, proof->z_1, public->G, bn_ctx);
  group_operation(rhs_gr_elem, proof->B_x, NULL, public->X, e, public->G, bn_ctx);
  is_verified &= group_elem_equal(lhs_gr_elem, rhs_gr_elem, public->G);

  scalar_free(e);
  scalar_free(temp);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  scalar_free(z_1_range);
  scalar_free(z_2_range);
  group_elem_free(lhs_gr_elem);
  group_elem_free(rhs_gr_elem);
  
  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t zkp_oper_group_commit_range_bytelen(uint64_t x_range_bytes, uint64_t y_range_bytes) {

  return  GROUP_ELEMENT_BYTES + 6*RING_PED_MODULUS_BYTES + 6*PAILLIER_MODULUS_BYTES + 3*x_range_bytes + y_range_bytes + 4*EPS_ZKP_SLACK_PARAMETER_BYTES;

}