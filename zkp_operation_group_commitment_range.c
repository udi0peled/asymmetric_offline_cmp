#include "zkp_operation_group_commitment_range.h"

zkp_operation_group_commitment_range_t *zkp_operation_group_commitment_range_new()
{
  zkp_operation_group_commitment_range_t *zkp = malloc(sizeof(*zkp));

  zkp->proof.B_x  = NULL;           // Group elements are created when proving
  zkp->proof.B_y  = scalar_new();
  zkp->proof.A    = scalar_new();
  zkp->proof.E    = scalar_new();
  zkp->proof.F    = scalar_new();
  zkp->proof.S    = scalar_new();
  zkp->proof.T    = scalar_new();
  zkp->proof.z_1  = scalar_new();
  zkp->proof.z_2  = scalar_new();
  zkp->proof.z_3  = scalar_new();
  zkp->proof.z_4  = scalar_new();
  zkp->proof.w    = scalar_new();
  zkp->proof.w_y  = scalar_new();

  return zkp;
}

void  zkp_operation_group_commitment_range_free   (zkp_operation_group_commitment_range_t *zkp)
{
  zkp->secret.x     = NULL;
  zkp->secret.y     = NULL;
  zkp->secret.rho   = NULL;
  zkp->secret.rho_y = NULL;

  group_elem_free(zkp->proof.B_x);
  scalar_free(zkp->proof.B_y);
  scalar_free(zkp->proof.A);
  scalar_free(zkp->proof.E);
  scalar_free(zkp->proof.F);
  scalar_free(zkp->proof.S);
  scalar_free(zkp->proof.T);
  scalar_free(zkp->proof.z_1);
  scalar_free(zkp->proof.z_2);
  scalar_free(zkp->proof.z_3);
  scalar_free(zkp->proof.z_4);
  scalar_free(zkp->proof.w);
  scalar_free(zkp->proof.w_y);

  free(zkp);
}

void zkp_operation_group_commitment_range_challenge (scalar_t e, zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N_0 paillier_N_1, rped_N_s_t, g, C, D, Y, X, A, B_x, B_y, E, F, S, T

  uint64_t fs_data_len = aux->info_len + 3*GROUP_ELEMENT_BYTES + 12*PAILLIER_MODULUS_BYTES + 7*RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub_0->N, 1);
  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , zkp->public.paillier_pub_1->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->s, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , zkp->public.rped_pub->t, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->public.g, zkp->public.G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->public.X, zkp->public.G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.C, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.Y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->public.D, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, zkp->proof.B_x, zkp->public.G, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.B_y, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, zkp->proof.A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.E, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.F, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.S, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, zkp->proof.T, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(zkp->public.G), fs_data, fs_data_len);
  scalar_make_plus_minus(e, ec_group_order(zkp->public.G));

  free(fs_data);
}


void zkp_operation_group_commitment_range_prove (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  if ((uint64_t) BN_num_bytes(zkp->secret.x) > zkp->public.x_range_bytes) return;
  if ((uint64_t) BN_num_bytes(zkp->secret.y) > zkp->public.y_range_bytes) return;
  if (!zkp->proof.B_x) zkp->proof.B_x = group_elem_new(zkp->public.G);

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

  BN_set_bit(alpha_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(alpha, alpha_range, 0);
  scalar_make_plus_minus(alpha, alpha_range);

  BN_set_bit(beta_range, 8*zkp->public.y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  scalar_sample_in_range(beta, beta_range, 0);
  scalar_make_plus_minus(beta, beta_range);

  BN_set_bit(gamma_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES);
  BN_mul(gamma_range, gamma_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(gamma, gamma_range, 0);
  scalar_make_plus_minus(gamma, gamma_range);
  scalar_sample_in_range(delta, gamma_range, 0);
  scalar_make_plus_minus(delta, gamma_range);
  
  BN_set_bit(mu_range, 8*zkp->public.x_range_bytes);
  BN_mul(mu_range, mu_range, zkp->public.rped_pub->N, bn_ctx);
  scalar_sample_in_range(mu, mu_range, 0);
  scalar_make_plus_minus(mu, mu_range);
  scalar_sample_in_range(m, mu_range, 0);
  scalar_make_plus_minus(m, mu_range);
  
  group_operation(zkp->proof.B_x, NULL, zkp->public.g, alpha, zkp->public.G);

  paillier_encryption_sample(r_y, zkp->public.paillier_pub_1);
  paillier_encryption_encrypt(zkp->proof.B_y, beta, r_y, zkp->public.paillier_pub_1);

  paillier_encryption_sample(r, zkp->public.paillier_pub_0);
  paillier_encryption_encrypt(temp, beta, r, zkp->public.paillier_pub_0);
  scalar_exp(zkp->proof.A, zkp->public.C, alpha, zkp->public.paillier_pub_0->N2);
  scalar_mul(zkp->proof.A, zkp->proof.A, temp, zkp->public.paillier_pub_0->N2);

  ring_pedersen_commit(zkp->proof.E, alpha, gamma, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.F, beta, delta, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.S, zkp->secret.x, m, zkp->public.rped_pub);
  ring_pedersen_commit(zkp->proof.T, zkp->secret.y, mu, zkp->public.rped_pub);

  zkp_operation_group_commitment_range_challenge(e, zkp, aux);
  
  BN_mul(temp, e, zkp->secret.x, bn_ctx);
  BN_add(zkp->proof.z_1, alpha, temp);

  BN_mul(temp, e, zkp->secret.y, bn_ctx);
  BN_add(zkp->proof.z_2, beta, temp);

  BN_mul(temp, e, m, bn_ctx);
  BN_add(zkp->proof.z_3, gamma, temp);

  BN_mul(temp, e, mu, bn_ctx);
  BN_add(zkp->proof.z_4, delta, temp);

  scalar_exp(temp, zkp->secret.rho, e, zkp->public.paillier_pub_0->N);
  scalar_mul(zkp->proof.w, r, temp, zkp->public.paillier_pub_0->N);

  scalar_exp(temp, zkp->secret.rho_y, e, zkp->public.paillier_pub_1->N);
  scalar_mul(zkp->proof.w_y, r_y, temp, zkp->public.paillier_pub_1->N);

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

int   zkp_operation_group_commitment_range_verify (zkp_operation_group_commitment_range_t *zkp, const zkp_aux_info_t *aux)
{
  scalar_t z_1_range = scalar_new();
  scalar_t z_2_range = scalar_new();
  BN_set_bit(z_1_range, 8*zkp->public.x_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);          // -1 since comparing signed range
  BN_set_bit(z_2_range, 8*zkp->public.y_range_bytes + 8*EPS_ZKP_SLACK_PARAMETER_BYTES - 1);

  int is_verified = (BN_ucmp(zkp->proof.z_1, z_1_range) < 0) && (BN_ucmp(zkp->proof.z_2, z_2_range) < 0);

  scalar_t e = scalar_new();
  zkp_operation_group_commitment_range_challenge(e, zkp, aux);

  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();
  scalar_t temp = scalar_new();

  paillier_encryption_encrypt(lhs_value, zkp->proof.z_2, zkp->proof.w_y, zkp->public.paillier_pub_1);
  scalar_exp(temp, zkp->public.Y, e, zkp->public.paillier_pub_1->N2);
  scalar_mul(rhs_value, zkp->proof.B_y, temp, zkp->public.paillier_pub_1->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  paillier_encryption_encrypt(temp, zkp->proof.z_2, zkp->proof.w, zkp->public.paillier_pub_0);
  scalar_exp(lhs_value, zkp->public.C, zkp->proof.z_1, zkp->public.paillier_pub_0->N2);
  scalar_mul(lhs_value, lhs_value, temp, zkp->public.paillier_pub_0->N2);
  scalar_exp(temp, zkp->public.D, e, zkp->public.paillier_pub_0->N2);
  scalar_mul(rhs_value, zkp->proof.A, temp, zkp->public.paillier_pub_0->N2);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_1, zkp->proof.z_3, zkp->public.rped_pub);
  scalar_exp(temp, zkp->proof.S, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.E, temp, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, zkp->proof.z_2, zkp->proof.z_4, zkp->public.rped_pub);
  scalar_exp(temp, zkp->proof.T, e, zkp->public.rped_pub->N);
  scalar_mul(rhs_value, zkp->proof.F, temp, zkp->public.rped_pub->N);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  gr_elem_t lhs_gr_elem = group_elem_new(zkp->public.G);
  gr_elem_t rhs_gr_elem = group_elem_new(zkp->public.G);

  group_operation(lhs_gr_elem, NULL, zkp->public.g, zkp->proof.z_1, zkp->public.G);
  group_operation(rhs_gr_elem, zkp->proof.B_x, zkp->public.X, e, zkp->public.G);
  is_verified &= group_elem_equal(lhs_gr_elem, rhs_gr_elem, zkp->public.G);

  scalar_free(e);
  scalar_free(temp);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  scalar_free(z_1_range);
  scalar_free(z_2_range);
  group_elem_free(lhs_gr_elem);
  group_elem_free(rhs_gr_elem);

  return is_verified;
}

void zkp_operation_group_commitment_range_proof_to_bytes(uint8_t **bytes, uint64_t *byte_len, const zkp_operation_group_commitment_range_t *zkp, uint64_t x_range_bytes, uint64_t y_range_bytes, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + 6*RING_PED_MODULUS_BYTES + 6*PAILLIER_MODULUS_BYTES + 3*x_range_bytes + y_range_bytes + 4*EPS_ZKP_SLACK_PARAMETER_BYTES;

  if ((!bytes) || (!*bytes) || (!zkp) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  uint8_t *set_bytes = *bytes;
 
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.A, 1);
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, zkp->proof.B_x, zkp->public.G, 1);
  scalar_to_bytes(&set_bytes, 2 * PAILLIER_MODULUS_BYTES, zkp->proof.B_y, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.E, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.F, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.S, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES, zkp->proof.T, 1);
  scalar_to_bytes(&set_bytes, x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES, zkp->proof.z_1, 1);
  scalar_to_bytes(&set_bytes, y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES, zkp->proof.z_2, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES, zkp->proof.z_3, 1);
  scalar_to_bytes(&set_bytes, RING_PED_MODULUS_BYTES + y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES, zkp->proof.z_4, 1);
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.w, 1);
  scalar_to_bytes(&set_bytes, PAILLIER_MODULUS_BYTES, zkp->proof.w_y, 1);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}