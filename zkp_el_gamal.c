#include <openssl/sha.h>
#include "zkp_el_gamal.h"

// TIME
#include <time.h>
clock_t zkp_eg_start_time, zkp_eg_end_time;
inline void start_timer() {
  zkp_eg_start_time = clock();
}

inline double get_time(const char* str) {
  zkp_eg_end_time = clock();
  double diff_time = ((double)(zkp_eg_end_time - zkp_eg_start_time)) /CLOCKS_PER_SEC;
  if (str) {
    printf(str);
    printf("%f\n", diff_time);
  }

  return diff_time;
}


zkp_el_gamal_proof_t *zkp_el_gamal_new (ec_group_t ec)
{
  zkp_el_gamal_proof_t *proof = malloc(sizeof(zkp_el_gamal_proof_t));
  
  proof->ec = ec;
  proof->A1 = group_elem_new(ec);
  proof->A2 = group_elem_new(ec);
  proof->z  = scalar_new();
  proof->w  = scalar_new();

  return proof;
}

void zkp_el_gamal_copy_anchor (zkp_el_gamal_proof_t * copy_anchor, zkp_el_gamal_proof_t * const anchor)
{
  group_elem_copy(copy_anchor->A1, anchor->A1);
  group_elem_copy(copy_anchor->A2, anchor->A2);
}

void zkp_el_gamal_free (zkp_el_gamal_proof_t *proof)
{
  group_elem_free(proof->A1);
  group_elem_free(proof->A2);
  scalar_free(proof->z);
  scalar_free(proof->w);
  free(proof);
}

void  zkp_el_gamal_anchor (zkp_el_gamal_proof_t *partial_proof, zkp_el_gamal_secret_t *partial_secret, const zkp_el_gamal_public_t *partial_public)
{
  ec_group_t ec = partial_public->ec;
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  start_timer();
  scalar_sample_in_range(partial_secret->lambda, ec_group_order(ec), 0, bn_ctx);
  scalar_sample_in_range(partial_secret->alpha, ec_group_order(ec), 0, bn_ctx);

  group_operation(partial_proof->A1, NULL, partial_secret->lambda, NULL, NULL, ec, bn_ctx);
  group_operation(partial_proof->A2, NULL, partial_secret->alpha, partial_public->Y, partial_secret->lambda, ec, bn_ctx);

  BN_CTX_free(bn_ctx);
}

void zkp_el_gamal_challenge(scalar_t *e, const zkp_el_gamal_proof_t *proof, const zkp_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = public->batch_size;

  uint64_t fs_data_len = aux->info_len + (4+2*batch_size)*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->ec, 1);
  
  for (uint64_t i = 0; i < batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B2[i], public->ec, 1);
  }
  
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A1, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A2, public->ec, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, batch_size, ec_group_order(public->ec), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_el_gamal_prove (zkp_el_gamal_proof_t *proof, const zkp_el_gamal_secret_t *secret, const zkp_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = public->batch_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t ec_order = ec_group_order(public->ec);
  scalar_t *e = scalar_array_new(batch_size);
  scalar_t temp = scalar_new();

  // Assumes anchor was generated already 
  zkp_el_gamal_challenge(e, proof, public, aux);

  scalar_copy(proof->z, secret->alpha);
  scalar_copy(proof->w, secret->lambda);

  for (uint64_t i = 0; i < batch_size; ++i ) {
    BN_mod_mul(temp, e[i], secret->k[i], ec_order, bn_ctx);
    BN_mod_add(proof->z, proof->z, temp, ec_order, bn_ctx);

    BN_mod_mul(temp, e[i], secret->b[i], ec_order, bn_ctx);
    BN_mod_add(proof->w, proof->w, temp, ec_order, bn_ctx);
  }

  scalar_array_free(e, batch_size);
  scalar_free(temp);
  BN_CTX_free(bn_ctx);
}

int   zkp_el_gamal_verify (const zkp_el_gamal_proof_t *proof, const zkp_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = public->batch_size;

  scalar_t  *e        = scalar_array_new(batch_size);
  scalar_t  *minus_e  = scalar_array_new(batch_size);

  int is_verified = 1;

  zkp_el_gamal_challenge(e, proof, public, aux);
  
  zkp_el_gamal_proof_t *computed_proof = zkp_el_gamal_new(public->ec);

  for (uint64_t i = 0; i < batch_size; ++i) scalar_negate(minus_e[i], e[i]);

  group_multi_oper(computed_proof->A1, proof->w, public->B1, minus_e, batch_size, public->ec, bn_ctx);

  is_verified &= (group_elem_equal(computed_proof->A1, proof->A1, public->ec) == 1);

  group_multi_oper(computed_proof->A2, proof->z, public->B2, minus_e, batch_size, public->ec, bn_ctx);
  group_operation(computed_proof->A2, computed_proof->A2, NULL, public->Y, proof->w, public->ec, bn_ctx);

  is_verified &= (group_elem_equal(computed_proof->A2, proof->A2, public->ec) == 1);

  zkp_el_gamal_free(computed_proof);
  scalar_array_free(e, batch_size);
  scalar_array_free(minus_e, batch_size);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_el_gamal_aggregate_anchors (zkp_el_gamal_proof_t *agg_anchor, zkp_el_gamal_proof_t ** const anchors, uint64_t num) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = agg_anchor->ec;
    
  group_operation(agg_anchor->A1, NULL, NULL, NULL, NULL, ec, bn_ctx);
  group_operation(agg_anchor->A2, NULL, NULL, NULL, NULL, ec, bn_ctx);

  for (uint64_t i = 0; i < num; ++i) {
    
    group_operation(agg_anchor->A1, agg_anchor->A1, NULL, anchors[i]->A1, NULL, ec, bn_ctx);
    group_operation(agg_anchor->A2, agg_anchor->A2, NULL, anchors[i]->A2, NULL, ec, bn_ctx);
  }   

  BN_CTX_free(bn_ctx);
}

void zkp_el_gamal_aggregate_local_proofs (zkp_el_gamal_proof_t *agg_proof, zkp_el_gamal_proof_t ** const local_proofs, uint64_t num) {

  ec_group_t ec = agg_proof->ec;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_set_ul(agg_proof->z, 0);
  scalar_set_ul(agg_proof->w, 0);

  for (uint64_t i = 0; i < num; ++i) {
    assert(group_elem_equal(agg_proof->A1, local_proofs[i]->A1, ec) == 1);
    assert(group_elem_equal(agg_proof->A2, local_proofs[i]->A2, ec) == 1);
    
    scalar_add(agg_proof->z, agg_proof->z, local_proofs[i]->z, ec_group_order(ec), bn_ctx);
    scalar_add(agg_proof->w, agg_proof->w, local_proofs[i]->w, ec_group_order(ec), bn_ctx);
  }   

  BN_CTX_free(bn_ctx);
}

uint64_t zkp_el_gamal_anchor_bytelen () {
  return 2*GROUP_ELEMENT_BYTES;
}

uint64_t zkp_el_gamal_proof_bytelen() {
  return 2*GROUP_ORDER_BYTES + zkp_el_gamal_anchor_bytelen();
}