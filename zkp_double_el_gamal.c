#include <openssl/sha.h>
#include "zkp_double_el_gamal.h"

zkp_double_el_gamal_proof_t *zkp_double_el_gamal_new (ec_group_t ec)
{
  zkp_double_el_gamal_proof_t *proof = malloc(sizeof(zkp_double_el_gamal_proof_t));
  
  proof->ec = ec;
  proof->U1 = group_elem_new(ec);
  proof->U2 = group_elem_new(ec);
  proof->W1 = group_elem_new(ec);
  proof->W2 = group_elem_new(ec);

  proof->z  = scalar_new();
  proof->w_1  = scalar_new();
  proof->w_2  = scalar_new();

  return proof;
}

void zkp_double_el_gamal_copy_anchor (zkp_double_el_gamal_proof_t * copy_anchor, zkp_double_el_gamal_proof_t * const anchor)
{
  group_elem_copy(copy_anchor->U1, anchor->U1);
  group_elem_copy(copy_anchor->U2, anchor->U2);
  group_elem_copy(copy_anchor->W1, anchor->W1);
  group_elem_copy(copy_anchor->W2, anchor->W2);
}

void zkp_double_el_gamal_free (zkp_double_el_gamal_proof_t *proof)
{
  group_elem_free(proof->W1);
  group_elem_free(proof->W2);
  group_elem_free(proof->U1);
  group_elem_free(proof->U2);

  scalar_free(proof->z);
  scalar_free(proof->w_1);
  scalar_free(proof->w_2);

  free(proof);
}

void  zkp_double_el_gamal_anchor (zkp_double_el_gamal_proof_t *partial_proof, zkp_double_el_gamal_secret_t *partial_secret, const zkp_double_el_gamal_public_t *partial_public)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = partial_public->ec;

  scalar_sample_in_range(partial_secret->alpha, ec_group_order(ec), 0, bn_ctx);
  scalar_sample_in_range(partial_secret->beta,  ec_group_order(ec), 0, bn_ctx);
  scalar_sample_in_range(partial_secret->gamma, ec_group_order(ec), 0, bn_ctx);

  group_operation(partial_proof->U1, NULL, partial_secret->beta, NULL, NULL, ec, bn_ctx);
  
  group_operation(partial_proof->U2, NULL, NULL, partial_public->Y, partial_secret->beta, ec, bn_ctx);
  group_operation(partial_proof->U2, partial_proof->U2, NULL, partial_public->X, partial_secret->alpha, ec, bn_ctx);

  group_operation(partial_proof->W1, NULL, partial_secret->gamma, NULL, NULL, ec, bn_ctx);
  group_operation(partial_proof->W2, NULL, partial_secret->alpha, partial_public->Y, partial_secret->gamma, ec, bn_ctx);

  BN_CTX_free(bn_ctx);

}

void zkp_double_el_gamal_challenge(scalar_t *e, const zkp_double_el_gamal_proof_t *proof, const zkp_double_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = public->batch_size;

  uint64_t fs_data_len = aux->info_len + (4*batch_size + 7)*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->ec, 1);

  for (uint64_t i = 0; i < batch_size; ++i) {

    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->V1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->V2[i], public->ec, 1);

    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B2[i], public->ec, 1);
  }

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->U1, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->U2, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W1, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W2, public->ec, 1);

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, batch_size, ec_group_order(public->ec), fs_data, fs_data_len);
  free(fs_data);
}

void zkp_double_el_gamal_prove (zkp_double_el_gamal_proof_t *proof, const zkp_double_el_gamal_secret_t *secret, const zkp_double_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = public->batch_size;

  scalar_t ec_order = ec_group_order(public->ec);
  scalar_t temp     = scalar_new();
  scalar_t *e       = scalar_array_new(batch_size);

  // Assumes anchor was generated already 
  zkp_double_el_gamal_challenge(e, proof, public, aux);

  scalar_copy(proof->z, secret->alpha);
  scalar_copy(proof->w_1, secret->beta);
  scalar_copy(proof->w_2, secret->gamma);

  for (uint64_t i = 0; i < public->batch_size; ++i) {

    scalar_mul(temp, e[i], secret->k[i], ec_order, bn_ctx);
    scalar_add(proof->z, proof->z, temp, ec_order, bn_ctx);

    scalar_mul(temp, e[i], secret->v[i], ec_order, bn_ctx);
    scalar_add(proof->w_1, proof->w_1, temp, ec_order, bn_ctx);

    scalar_mul(temp, e[i], secret->b[i], ec_order, bn_ctx);
    scalar_add(proof->w_2, proof->w_2, temp, ec_order, bn_ctx);
  }

  scalar_free(temp);
  scalar_array_free(e, batch_size);
  BN_CTX_free(bn_ctx);
}

int   zkp_double_el_gamal_verify (const zkp_double_el_gamal_proof_t *proof, const zkp_double_el_gamal_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = public->batch_size;
  ec_group_t ec = public->ec;

  //scalar_t  minus_e = scalar_new();
  scalar_t  *e       = scalar_array_new(batch_size);
  scalar_t  *minus_e = scalar_array_new(batch_size);

  int is_verified = 1;

  zkp_double_el_gamal_challenge(e, proof, public, aux);
  
  for (uint64_t i = 0; i < batch_size; ++i) scalar_negate(minus_e[i], e[i]);

  zkp_double_el_gamal_proof_t *computed_proof = zkp_double_el_gamal_new(ec);

  group_multi_oper(computed_proof->U1, proof->w_1, public->V1, minus_e, batch_size, ec, bn_ctx);
  
  group_multi_oper(computed_proof->U2, NULL, public->V2, minus_e, batch_size, ec, bn_ctx);
  group_operation(computed_proof->U2, computed_proof->U2, NULL, public->X, proof->z, ec, bn_ctx);
  group_operation(computed_proof->U2, computed_proof->U2, NULL, public->Y, proof->w_1, ec, bn_ctx);

  group_multi_oper(computed_proof->W1, proof->w_2, public->B1, minus_e, batch_size, ec, bn_ctx);

  group_multi_oper(computed_proof->W2, proof->z, public->B2, minus_e, batch_size, ec, bn_ctx);
  group_operation(computed_proof->W2, computed_proof->W2, NULL, public->Y, proof->w_2, ec, bn_ctx);

  is_verified &= (group_elem_equal(computed_proof->U1, proof->U1, ec) == 1);
  is_verified &= (group_elem_equal(computed_proof->U2, proof->U2, ec) == 1);
  is_verified &= (group_elem_equal(computed_proof->W1, proof->W1, ec) == 1);
  is_verified &= (group_elem_equal(computed_proof->W2, proof->W2, ec) == 1);
  
  zkp_double_el_gamal_free(computed_proof);
  scalar_array_free(e, batch_size);
  scalar_array_free(minus_e, batch_size);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_double_el_gamal_aggregate_anchors (zkp_double_el_gamal_proof_t *agg_anchor, zkp_double_el_gamal_proof_t ** anchors, uint64_t num) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = agg_anchor->ec;

  EC_POINT_set_to_infinity(ec, agg_anchor->U1);
  EC_POINT_set_to_infinity(ec, agg_anchor->U2);
  EC_POINT_set_to_infinity(ec, agg_anchor->W1);
  EC_POINT_set_to_infinity(ec, agg_anchor->W2);

  for (uint64_t i = 0; i < num; ++i) {
    
    EC_POINT_add(ec, agg_anchor->U1, agg_anchor->U1, anchors[i]->U1, bn_ctx);
    EC_POINT_add(ec, agg_anchor->U2, agg_anchor->U2, anchors[i]->U2, bn_ctx);
    EC_POINT_add(ec, agg_anchor->W1, agg_anchor->W1, anchors[i]->W1, bn_ctx);
    EC_POINT_add(ec, agg_anchor->W2, agg_anchor->W2, anchors[i]->W2, bn_ctx);
  }   
  
  BN_CTX_free(bn_ctx);
}

void zkp_double_el_gamal_aggregate_local_proofs (zkp_double_el_gamal_proof_t *agg_proof, zkp_double_el_gamal_proof_t ** local_proofs, uint64_t num) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = agg_proof->ec;
    
  scalar_set_ul(agg_proof->z, 0);
  scalar_set_ul(agg_proof->w_1, 0);
  scalar_set_ul(agg_proof->w_2, 0);

  for (uint64_t i = 0; i < num; ++i) {

    assert(group_elem_equal(agg_proof->U1, local_proofs[i]->U1, ec) == 1);
    assert(group_elem_equal(agg_proof->U2, local_proofs[i]->U2, ec) == 1);
    assert(group_elem_equal(agg_proof->W1, local_proofs[i]->W1, ec) == 1);
    assert(group_elem_equal(agg_proof->W2, local_proofs[i]->W2, ec) == 1);
    
    scalar_add(agg_proof->z, agg_proof->z, local_proofs[i]->z, ec_group_order(ec), bn_ctx);
    scalar_add(agg_proof->w_1, agg_proof->w_1, local_proofs[i]->w_1, ec_group_order(ec), bn_ctx);
    scalar_add(agg_proof->w_2, agg_proof->w_2, local_proofs[i]->w_2, ec_group_order(ec), bn_ctx);
  }   

  BN_CTX_free(bn_ctx);

}

uint64_t zkp_double_el_gamal_anchor_bytelen () {
  return 4*GROUP_ELEMENT_BYTES;
}

uint64_t zkp_double_el_gamal_proof_bytelen() {
  return 3*GROUP_ORDER_BYTES + zkp_double_el_gamal_anchor_bytelen();
}