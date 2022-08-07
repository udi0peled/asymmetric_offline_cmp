#include "zkp_tight_range.h"
#include "common.h"
#include <openssl/sha.h>

#define SOUNDNESS_ELL 256
#define SLACKNESS_EPS (SOUNDNESS_ELL + 64)

zkp_tight_range_proof_t *zkp_tight_range_new ()
{
  zkp_tight_range_proof_t *proof = malloc(sizeof(zkp_tight_range_proof_t));

  proof->S      = scalar_new();
  proof->T_1    = scalar_new();
  proof->T_2    = scalar_new();
  proof->T_3    = scalar_new();

  proof->z_1    = scalar_new();
  proof->z_2    = scalar_new();
  proof->z_3    = scalar_new();
  proof->w_1    = scalar_new();
  proof->w_2    = scalar_new();
  proof->w_3    = scalar_new();
  proof->sigma  = scalar_new();
  proof->tau    = scalar_new();
  proof->delta  = scalar_new();
  proof->eta    = scalar_new();

  return proof;
}

void  zkp_tight_range_free   (zkp_tight_range_proof_t *proof)
{
  scalar_free(proof->S);
  scalar_free(proof->T_1);
  scalar_free(proof->T_2);
  scalar_free(proof->T_3);

  scalar_free(proof->z_1);
  scalar_free(proof->z_2);
  scalar_free(proof->z_3);
  scalar_free(proof->w_1);
  scalar_free(proof->w_2);
  scalar_free(proof->w_3);

  scalar_free(proof->sigma);
  scalar_free(proof->tau);
  scalar_free(proof->delta);
  scalar_free(proof->eta);

  free(proof);
}

void zkp_tight_range_challenge (scalar_t e, const zkp_tight_range_proof_t *proof, const zkp_tight_range_public_t *public, const zkp_aux_info_t *aux)
{
  // Fiat-Shamir on paillier_N, rped_N_s_t, g, X, W, S, T_1, T_2, T_3 and sha512 of anchor 

  uint64_t fs_data_len = aux->info_len + 2*GROUP_ELEMENT_BYTES + 3*PAILLIER_MODULUS_BYTES + 7*RING_PED_MODULUS_BYTES + sizeof(proof->anchor_hash);
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s[0], 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->ec, 1);
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->W, 1);
  
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->S, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->T_1, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->T_2, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES, proof->T_3, 1);
  
  memcpy(data_pos, proof->anchor_hash, sizeof(proof->anchor_hash));
  data_pos += sizeof(proof->anchor_hash);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(&e, 1, ec_group_order(public->ec), fs_data, fs_data_len);
  scalar_make_signed(e, ec_group_order(public->ec));

  free(fs_data);
}

void zkp_tight_range_positive_from_secret(scalar_t positive, const scalar_t secret, uint64_t secret_bitlength) {
  // Compute 4*x*(2^ell-x)+1
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t two_power = scalar_new();
  scalar_t res_pos = scalar_new();

  scalar_set_power_of_2(two_power, secret_bitlength);
  BN_sub(res_pos, two_power, secret);
  BN_mul(res_pos, res_pos, secret, bn_ctx);
  BN_lshift(res_pos, res_pos, 2);
  BN_add_word(res_pos, 1);

  BN_copy(positive, res_pos);

  scalar_free(two_power);
  scalar_free(res_pos);
  BN_CTX_free(bn_ctx);
}

zkp_tight_range_positive_splitting_t *zkp_tight_range_splitting_new (scalar_t secret) {

  zkp_tight_range_positive_splitting_t *splitting = malloc(sizeof(zkp_tight_range_positive_splitting_t));
  
  splitting->alpha_1 = scalar_new();
  splitting->alpha_2 = scalar_new();
  splitting->alpha_3 = scalar_new();

  assert(BN_num_bits(secret) <= SOUNDNESS_ELL);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t positive   = scalar_new();
  scalar_t temp       = scalar_new();
  scalar_t range      = scalar_new();
  scalar_t test       = scalar_new();
  scalar_t exp_test   = scalar_new();
  scalar_t prime_diff = scalar_new();
  scalar_t b          = scalar_new();
  scalar_t a          = scalar_new();
  scalar_t r0         = scalar_new();

  zkp_tight_range_positive_from_secret(positive, secret, SOUNDNESS_ELL);

  scalar_set_power_of_2(range, SOUNDNESS_ELL/2 - 1);

  BN_set_word(prime_diff, 6);
  
  while (BN_is_prime_ex(prime_diff, 128, bn_ctx, NULL) != 1) {
    BN_rand_range(splitting->alpha_1, range);
    BN_mul_word(splitting->alpha_1, 2);
    BN_sqr(temp, splitting->alpha_1, bn_ctx);
    BN_sub(prime_diff, positive, temp);
  }
  
  BN_copy(exp_test, prime_diff);
  BN_sub_word(exp_test, 1);
  BN_div_word(exp_test, 2);

  BN_set_word(test, 1);

  while (BN_cmp(test, prime_diff) != 0) {
    BN_rand_range(b, prime_diff);
    BN_mod_exp(test, b, exp_test, prime_diff, bn_ctx);
    BN_add_word(test, 1);
  }

  BN_div_word(exp_test, 2);
  BN_mod_exp(b, b, exp_test, prime_diff, bn_ctx);

  BN_copy(r0, prime_diff);
  BN_copy(temp, prime_diff);

  while (BN_cmp(temp, prime_diff) >= 0) {
    BN_copy(a, b);
    BN_copy(b, r0);
    BN_mod(r0, a, b, bn_ctx);

    BN_sqr(temp, r0, bn_ctx);
  }

  BN_copy(splitting->alpha_2, r0);
  BN_mod(splitting->alpha_3, b, r0, bn_ctx);
  
  // Sanity check of valid splittings
  BN_sqr(a, splitting->alpha_1, bn_ctx);
  BN_sqr(b, splitting->alpha_2, bn_ctx);
  BN_sqr(r0, splitting->alpha_3, bn_ctx);

  BN_add(r0, r0, a);
  BN_add(r0, r0, b);
  assert(BN_cmp(r0, positive) == 0);

  scalar_free(positive);
  scalar_free(temp);
  scalar_free(range);
  scalar_free(test);
  scalar_free(exp_test);
  scalar_free(prime_diff);
  scalar_free(b);
  scalar_free(a);
  scalar_free(r0);

  BN_CTX_free(bn_ctx);

  return splitting;
}

void zkp_tight_range_splitting_free(zkp_tight_range_positive_splitting_t *splitting) {
  scalar_free(splitting->alpha_1);
  scalar_free(splitting->alpha_2);
  scalar_free(splitting->alpha_3);
  free(splitting);
}

void zkp_tight_range_prove (zkp_tight_range_proof_t *proof, const zkp_tight_range_secret_t *secret, const zkp_tight_range_public_t *public, const zkp_aux_info_t *aux)
{  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t temp_range = scalar_new();
  scalar_t temp       = scalar_new();
  scalar_t gamma      = scalar_new();
  scalar_t omega      = scalar_new();
  scalar_t beta       = scalar_new();
  scalar_t y_1        = scalar_new();
  scalar_t y_2        = scalar_new();
  scalar_t y_3        = scalar_new();
  scalar_t v_1        = scalar_new();
  scalar_t v_2        = scalar_new();
  scalar_t v_3        = scalar_new();
  scalar_t r          = scalar_new();
  scalar_t mu         = scalar_new();
  scalar_t lambda_1   = scalar_new();
  scalar_t lambda_2   = scalar_new();
  scalar_t lambda_3   = scalar_new();
  scalar_t lambda     = scalar_new();
  scalar_t U          = scalar_new();
  scalar_t V_1        = scalar_new();
  scalar_t V_2        = scalar_new();
  scalar_t V_3        = scalar_new();
  scalar_t D          = scalar_new();
  scalar_t C          = scalar_new();
  scalar_t e          = scalar_new();
  gr_elem_t Y         = group_elem_new(public->ec);
  
  // Sample proof randmoness

  BN_lshift(temp_range, public->rped_pub->N, SOUNDNESS_ELL);

  scalar_sample_in_range(mu, temp_range, 0, bn_ctx);
  scalar_sample_in_range(lambda_1, temp_range, 0, bn_ctx);
  scalar_sample_in_range(lambda_2, temp_range, 0, bn_ctx);
  scalar_sample_in_range(lambda_3, temp_range, 0, bn_ctx);
  
  scalar_make_signed(mu, temp_range);
  scalar_make_signed(lambda_1, temp_range);
  scalar_make_signed(lambda_2, temp_range);
  scalar_make_signed(lambda_3, temp_range);

  scalar_set_power_of_2(temp_range, SOUNDNESS_ELL + SLACKNESS_EPS);

  scalar_sample_in_range(gamma, temp_range, 0, bn_ctx);
  scalar_sample_in_range(y_1, temp_range, 0, bn_ctx);
  scalar_sample_in_range(y_2, temp_range, 0, bn_ctx);
  scalar_sample_in_range(y_3, temp_range, 0, bn_ctx);

  scalar_make_signed(gamma, temp_range);
  scalar_make_signed(y_1, temp_range);
  scalar_make_signed(y_2, temp_range);
  scalar_make_signed(y_3, temp_range);

  BN_lshift(temp_range, public->rped_pub->N, SOUNDNESS_ELL + SLACKNESS_EPS);
  
  scalar_sample_in_range(omega, temp_range, 0, bn_ctx);
  scalar_sample_in_range(v_1, temp_range, 0, bn_ctx);
  scalar_sample_in_range(v_2, temp_range, 0, bn_ctx);
  scalar_sample_in_range(v_3, temp_range, 0, bn_ctx);

  scalar_make_signed(omega, temp_range);
  scalar_make_signed(v_1, temp_range);
  scalar_make_signed(v_2, temp_range);
  scalar_make_signed(v_3, temp_range);

  BN_lshift(temp_range, public->rped_pub->N, 2*SOUNDNESS_ELL + SLACKNESS_EPS);

  scalar_sample_in_range(beta, temp_range, 0, bn_ctx);
  scalar_make_signed(beta, temp_range);

  scalar_sample_in_range(r, public->paillier_pub->N, 1, bn_ctx);

  // Start computing anchors

  ring_pedersen_commit(proof->S, &secret->x, 1, mu, public->rped_pub);
  ring_pedersen_commit(proof->T_1, &secret->splitting->alpha_1, 1, lambda_1, public->rped_pub);
  ring_pedersen_commit(proof->T_2, &secret->splitting->alpha_2, 1, lambda_2, public->rped_pub);
  ring_pedersen_commit(proof->T_3, &secret->splitting->alpha_3, 1, lambda_3, public->rped_pub);

  group_operation(Y, NULL, gamma, NULL, NULL, public->ec, bn_ctx);

  ring_pedersen_commit(U, &gamma, 1, omega, public->rped_pub);
  ring_pedersen_commit(V_1, &y_1, 1, v_1, public->rped_pub);
  ring_pedersen_commit(V_2, &y_2, 1, v_2, public->rped_pub);
  ring_pedersen_commit(V_3, &y_3, 1, v_3, public->rped_pub);

  paillier_encryption_encrypt(D, gamma, r, public->paillier_pub);

  BN_lshift(temp, gamma, SOUNDNESS_ELL);
  ring_pedersen_commit(C, &temp, 1, beta, public->rped_pub);
  BN_mod_inverse(C, C, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->S, gamma, public->rped_pub->N, bn_ctx);
  scalar_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_1, y_1, public->rped_pub->N, bn_ctx);
  scalar_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_2, y_2, public->rped_pub->N, bn_ctx);
  scalar_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_3, y_3, public->rped_pub->N, bn_ctx);
  scalar_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  uint8_t *hash_bytes = malloc(2*PAILLIER_MODULUS_BYTES);
  
  SHA512_CTX anchor_hash_ctx;
  SHA512_Init(&anchor_hash_ctx);

  group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, Y, public->ec, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, U, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_1, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_2, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_3, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, 2*PAILLIER_MODULUS_BYTES, D, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, 2*PAILLIER_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, C, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  SHA512_Final(proof->anchor_hash, &anchor_hash_ctx);

  zkp_tight_range_challenge(e, proof, public, aux);

  BN_mul(proof->z_1, e, secret->splitting->alpha_1, bn_ctx);
  BN_add(proof->z_1, y_1, proof->z_1);

  BN_mul(proof->z_2, e, secret->splitting->alpha_2, bn_ctx);
  BN_add(proof->z_2, y_2, proof->z_2);

  BN_mul(proof->z_3, e, secret->splitting->alpha_3, bn_ctx);
  BN_add(proof->z_3, y_3, proof->z_3);

  BN_mul(proof->w_1, e, lambda_1, bn_ctx);
  BN_add(proof->w_1, v_1, proof->w_1);

  BN_mul(proof->w_2, e, lambda_2, bn_ctx);
  BN_add(proof->w_2, v_2, proof->w_2);

  BN_mul(proof->w_3, e, lambda_3, bn_ctx);
  BN_add(proof->w_3, v_3, proof->w_3);

  BN_mul(proof->sigma, e, secret->x, bn_ctx);
  BN_mul_word(proof->sigma, 4);
  BN_add(proof->sigma, gamma, proof->sigma);

  BN_mul(proof->tau, e, mu, bn_ctx);
  BN_mul_word(proof->tau, 4);
  BN_add(proof->tau, omega, proof->tau);

  BN_mul(lambda, secret->x, mu, bn_ctx);
  BN_mul_word(lambda, 4);
  BN_mul(temp, secret->splitting->alpha_1, lambda_1, bn_ctx);
  BN_add(lambda, lambda, temp);
  BN_mul(temp, secret->splitting->alpha_2, lambda_2, bn_ctx);
  BN_add(lambda, lambda, temp);
  BN_mul(temp, secret->splitting->alpha_3, lambda_3, bn_ctx);
  BN_add(lambda, lambda, temp);

  BN_mul(proof->delta, e, lambda, bn_ctx);
  BN_add(proof->delta, beta, proof->delta);

  BN_set_word(temp, 4);
  scalar_exp(proof->eta, secret->rho, e, public->paillier_pub->N, bn_ctx);
  scalar_exp(proof->eta, proof->eta, temp, public->paillier_pub->N, bn_ctx);
  scalar_mul(proof->eta, r, proof->eta, public->paillier_pub->N, bn_ctx);
  
  scalar_free(temp_range);
  scalar_free(temp);
  scalar_free(gamma);
  scalar_free(omega);
  scalar_free(beta);
  scalar_free(y_1);
  scalar_free(y_2);
  scalar_free(y_3);
  scalar_free(v_1);
  scalar_free(v_2);
  scalar_free(v_3);
  scalar_free(r);
  scalar_free(mu);
  scalar_free(lambda_1);
  scalar_free(lambda_2);
  scalar_free(lambda_3);
  scalar_free(lambda);
  scalar_free(U);
  scalar_free(V_1);
  scalar_free(V_2);
  scalar_free(V_3);
  scalar_free(D);
  scalar_free(C);
  scalar_free(e);

  group_elem_free(Y);

  free(hash_bytes);
  BN_CTX_free(bn_ctx);
}

int   zkp_tight_range_verify (const zkp_tight_range_proof_t *proof, const zkp_tight_range_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_new();

  scalar_t U        = scalar_new();
  scalar_t V_1      = scalar_new();
  scalar_t V_2      = scalar_new();
  scalar_t V_3      = scalar_new();
  scalar_t D        = scalar_new();
  scalar_t C        = scalar_new();
  scalar_t temp     = scalar_new();
  scalar_t e        = scalar_new();
  scalar_t minus_e  = scalar_new();
  scalar_t minus_4e = scalar_new();
  gr_elem_t Y       = group_elem_new(public->ec);

  int is_verified = 1;

  is_verified &= ( BN_num_bits(proof->sigma) <= SOUNDNESS_ELL + SLACKNESS_EPS - 1 );

  zkp_tight_range_challenge(e, proof, public, aux);
  scalar_negate(minus_e, e);
  BN_copy(minus_4e, minus_e);
  BN_mul_word(minus_4e, 4);

  group_operation(Y, NULL, proof->sigma, NULL, NULL, public->ec, bn_ctx);
  group_operation(Y, Y, NULL, public->X, minus_4e, public->ec, bn_ctx);

  ring_pedersen_commit(U, &proof->sigma, 1, proof->tau, public->rped_pub);
  scalar_exp(temp, proof->S, minus_4e, public->rped_pub->N, bn_ctx);
  BN_mod_mul(U, U, temp, public->rped_pub->N, bn_ctx);
 
  ring_pedersen_commit(V_1, &proof->z_1, 1, proof->w_1, public->rped_pub);
  scalar_exp(temp, proof->T_1, minus_e, public->rped_pub->N, bn_ctx);
  BN_mod_mul(V_1, V_1, temp, public->rped_pub->N, bn_ctx);

  ring_pedersen_commit(V_2, &proof->z_2, 1, proof->w_2, public->rped_pub);
  scalar_exp(temp, proof->T_2, minus_e, public->rped_pub->N, bn_ctx);
  BN_mod_mul(V_2, V_2, temp, public->rped_pub->N, bn_ctx);

  ring_pedersen_commit(V_3, &proof->z_3, 1, proof->w_3, public->rped_pub);
  scalar_exp(temp, proof->T_3, minus_e, public->rped_pub->N, bn_ctx);
  BN_mod_mul(V_3, V_3, temp, public->rped_pub->N, bn_ctx);

  paillier_encryption_encrypt(D, proof->sigma, proof->eta, public->paillier_pub);
  paillier_encryption_homomorphic(D, public->W, minus_4e, D, public->paillier_pub);

  scalar_negate(temp, proof->delta);
  ring_pedersen_commit(C, &minus_e, 1, temp, public->rped_pub);

  scalar_set_power_of_2(temp, SOUNDNESS_ELL);
  scalar_negate(temp, temp);
  scalar_exp(temp, public->rped_pub->s[0], temp, public->rped_pub->N, bn_ctx);
  scalar_mul(temp, temp, proof->S, public->rped_pub->N, bn_ctx);
  scalar_exp(temp, temp, proof->sigma, public->rped_pub->N, bn_ctx);
  scalar_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_1, proof->z_1, public->rped_pub->N, bn_ctx);
  BN_mod_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_2, proof->z_2, public->rped_pub->N, bn_ctx);
  BN_mod_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  scalar_exp(temp, proof->T_3, proof->z_3, public->rped_pub->N, bn_ctx);
  BN_mod_mul(C, C, temp, public->rped_pub->N, bn_ctx);

  uint8_t *hash_bytes = malloc(2*PAILLIER_MODULUS_BYTES);

  hash_chunk computed_anchor_hash;
  SHA512_CTX anchor_hash_ctx;
  SHA512_Init(&anchor_hash_ctx);

  group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, Y, public->ec, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);
 
  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, U, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_1, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_2, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, V_3, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, 2*PAILLIER_MODULUS_BYTES, D, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, 2*PAILLIER_MODULUS_BYTES);

  scalar_to_bytes(&hash_bytes, RING_PED_MODULUS_BYTES, C, 0);
  SHA512_Update(&anchor_hash_ctx, hash_bytes, RING_PED_MODULUS_BYTES);

  SHA512_Final(computed_anchor_hash, &anchor_hash_ctx);

  is_verified &= (memcmp(proof->anchor_hash, computed_anchor_hash, sizeof(computed_anchor_hash)) == 0);
  
  group_elem_free(Y);
  scalar_free(e);
  scalar_free(U);
  scalar_free(V_1);
  scalar_free(V_2);
  scalar_free(V_3);
  scalar_free(D);
  scalar_free(C);
  scalar_free(temp);
  scalar_free(minus_e);
  scalar_free(minus_4e);

  free(hash_bytes);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t  zkp_tight_range_proof_bytelen () {
  return PAILLIER_MODULUS_BYTES + 5*RING_PED_MODULUS_BYTES + 10*SOUNDNESS_ELL/8 + 9*SLACKNESS_EPS/8 + sizeof(hash_chunk);
}

