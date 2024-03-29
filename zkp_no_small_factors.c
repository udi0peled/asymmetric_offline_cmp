#include "zkp_no_small_factors.h"

#define SOUNDNESS_ELL 256
#define SLACKNESS_EPS (SOUNDNESS_ELL + 64)

zkp_no_small_factors_t *zkp_no_small_factors_new ()
{
  zkp_no_small_factors_t *proof = malloc(sizeof(zkp_no_small_factors_t));

  proof->P = scalar_new();
  proof->Q = scalar_new();
  proof->A = scalar_new();
  proof->B = scalar_new();
  proof->T = scalar_new();

  proof->z_1 = scalar_new();
  proof->z_2 = scalar_new();
  proof->w_1 = scalar_new();
  proof->w_2 = scalar_new();
  proof->v   = scalar_new();

  return proof;
}

void  zkp_no_small_factors_free (zkp_no_small_factors_t *proof)
{
  scalar_free(proof->P);
  scalar_free(proof->Q);
  scalar_free(proof->A);
  scalar_free(proof->B);
  scalar_free(proof->T);

  scalar_free(proof->z_1);
  scalar_free(proof->z_2);
  scalar_free(proof->w_1);
  scalar_free(proof->w_2);
  scalar_free(proof->v);

  free(proof);
}

void zkp_no_small_factors_challenge (scalar_t e, const zkp_no_small_factors_t *proof, const paillier_public_key_t *paillier_pub, const ring_pedersen_public_t *rped_pub, const zkp_aux_info_t *aux)
{
  assert(RING_PEDERSEN_MULTIPLICITY >= 1);

  // Fiat-Shamir on paillier: N, rped: N, s, t, proof: P, A, B, T
  uint64_t fs_data_len = aux->info_len + 8*RING_PED_MODULUS_BYTES + PAILLIER_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , rped_pub->t, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , rped_pub->s[0], 1);

  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->P, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->Q, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->A, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->B, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , proof->T, 1);

  assert(fs_data + fs_data_len == data_pos);

  scalar_t challange_range = scalar_new();
  scalar_set_power_of_2(challange_range, SOUNDNESS_ELL);

  fiat_shamir_scalars_in_range(&e, 1, challange_range, fs_data, fs_data_len);
  scalar_make_signed(e, challange_range);

  scalar_free(challange_range);
  free(fs_data);
}

void zkp_no_small_factors_prove (zkp_no_small_factors_t *proof, const paillier_private_key_t *paillier_priv, const ring_pedersen_public_t *rped_pub, const zkp_aux_info_t *aux)
{
  assert(BN_num_bits(paillier_priv->p) == BN_num_bits(paillier_priv->q)); // Assumed by choosing k = +1 in r range

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t temp_range  = scalar_new();
  scalar_t alpha       = scalar_new();
  scalar_t beta        = scalar_new();
  scalar_t mu          = scalar_new();
  scalar_t sigma       = scalar_new();
  scalar_t r           = scalar_new();
  scalar_t x           = scalar_new();
  scalar_t y           = scalar_new();
  scalar_t e           = scalar_new();

  scalar_set_power_of_2(temp_range, SOUNDNESS_ELL + SLACKNESS_EPS + 4*PAILLIER_MODULUS_BYTES);
  
  scalar_sample_in_range(alpha, temp_range, 0, bn_ctx);
  scalar_sample_in_range(beta, temp_range, 0, bn_ctx);

  scalar_make_signed(alpha, temp_range);
  scalar_make_signed(beta, temp_range);

  BN_lshift(temp_range, rped_pub->N, SOUNDNESS_ELL);
  
  scalar_sample_in_range(mu, temp_range, 0, bn_ctx);
  scalar_sample_in_range(sigma, temp_range, 0, bn_ctx);

  scalar_make_signed(mu, temp_range);
  scalar_make_signed(sigma, temp_range);
  
  BN_lshift(temp_range, rped_pub->N, SOUNDNESS_ELL + SLACKNESS_EPS + 1 + 4*PAILLIER_MODULUS_BYTES);
  
  scalar_sample_in_range(r, temp_range, 0, bn_ctx);
  scalar_make_signed(r, temp_range);
  
  BN_lshift(temp_range, rped_pub->N, SOUNDNESS_ELL + SLACKNESS_EPS);
  
  scalar_sample_in_range(x, temp_range, 0, bn_ctx);
  scalar_sample_in_range(y, temp_range, 0, bn_ctx);

  scalar_make_signed(x, temp_range);
  scalar_make_signed(y, temp_range);

  ring_pedersen_commit(proof->P, &paillier_priv->p, 1, mu, rped_pub);
  ring_pedersen_commit(proof->Q, &paillier_priv->q, 1, sigma, rped_pub);
  ring_pedersen_commit(proof->A, &alpha, 1, x, rped_pub);
  ring_pedersen_commit(proof->B, &beta, 1, y, rped_pub);

  scalar_exp(proof->T, proof->Q, alpha, rped_pub->N, bn_ctx);
  scalar_exp(temp_range, rped_pub->t, r, rped_pub->N, bn_ctx);
  BN_mod_mul(proof->T, proof->T, temp_range, rped_pub->N, bn_ctx);

  paillier_public_key_t *paillier_pub = paillier_encryption_public_new();
  paillier_encryption_copy_keys(NULL, paillier_pub, paillier_priv, NULL);

  zkp_no_small_factors_challenge(e, proof, paillier_pub, rped_pub, aux);

  BN_mul(proof->z_1, e, paillier_priv->p, bn_ctx);
  BN_add(proof->z_1, alpha, proof->z_1);

  BN_mul(proof->z_2, e, paillier_priv->q, bn_ctx);
  BN_add(proof->z_2, beta, proof->z_2);

  BN_mul(proof->w_1, e, mu, bn_ctx);
  BN_add(proof->w_1, x, proof->w_1);

  BN_mul(proof->w_2, e, sigma, bn_ctx);
  BN_add(proof->w_2, y, proof->w_2);

  BN_mul(proof->v, e, sigma, bn_ctx);
  BN_mul(proof->v, proof->v, paillier_priv->p, bn_ctx);
  BN_sub(proof->v, r, proof->v);
  
  scalar_free(temp_range);
  scalar_free(alpha);
  scalar_free(beta);
  scalar_free(mu);
  scalar_free(sigma);
  scalar_free(r);
  scalar_free(x);
  scalar_free(y);
  scalar_free(e);
  
  paillier_encryption_free_keys(NULL, paillier_pub);
  BN_CTX_free(bn_ctx);
}

int  zkp_no_small_factors_verify (zkp_no_small_factors_t *proof, const paillier_public_key_t *paillier_pub, const ring_pedersen_public_t *rped_pub, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t temp = scalar_new();

  int is_verified = 1;

  is_verified &= ( BN_num_bits(proof->z_1) <= SOUNDNESS_ELL + SLACKNESS_EPS + 4*PAILLIER_MODULUS_BYTES );
  is_verified &= ( BN_num_bits(proof->z_2) <= SOUNDNESS_ELL + SLACKNESS_EPS + 4*PAILLIER_MODULUS_BYTES );

  scalar_t e = scalar_new();
  zkp_no_small_factors_challenge(e, proof, paillier_pub, rped_pub, aux);
    
  scalar_t lhs_value = scalar_new();
  scalar_t rhs_value = scalar_new();

  ring_pedersen_commit(lhs_value, &proof->z_1, 1, proof->w_1, rped_pub);
  scalar_exp(rhs_value, proof->P, e, rped_pub->N, bn_ctx);
  scalar_mul(rhs_value, rhs_value, proof->A, rped_pub->N, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  ring_pedersen_commit(lhs_value, &proof->z_2, 1, proof->w_2, rped_pub);
  scalar_exp(rhs_value, proof->Q, e, rped_pub->N, bn_ctx);
  scalar_mul(rhs_value, rhs_value, proof->B, rped_pub->N, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);

  scalar_exp(lhs_value, proof->Q, proof->z_1, rped_pub->N, bn_ctx);
  scalar_exp(temp, rped_pub->t, proof->v, rped_pub->N, bn_ctx);
  scalar_mul(lhs_value, lhs_value, temp, rped_pub->N, bn_ctx);

  scalar_exp(rhs_value, rped_pub->s[0], paillier_pub->N, rped_pub->N, bn_ctx);
  scalar_exp(rhs_value, rhs_value, e, rped_pub->N, bn_ctx);
  scalar_mul(rhs_value, proof->T, rhs_value, rped_pub->N, bn_ctx);
  is_verified &= scalar_equal(lhs_value, rhs_value);
  
  scalar_free(e);
  scalar_free(temp);
  scalar_free(lhs_value);
  scalar_free(rhs_value);
  
  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t zkp_no_small_factors_proof_bytelen()
{
  return 4*RING_PED_MODULUS_BYTES + 5*(SOUNDNESS_ELL+SLACKNESS_EPS)/4 + 3*(PAILLIER_MODULUS_BYTES+1)/2 + 3*RING_PED_MODULUS_BYTES;
}