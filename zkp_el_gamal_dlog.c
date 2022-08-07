#include <openssl/sha.h>
#include "zkp_el_gamal_dlog.h"

// TIME
#include <time.h>
clock_t zkp_egd_start_time, zkp_egd_end_time;
inline void start_timer() {
  zkp_egd_start_time = clock();
}

inline double get_time(const char* str) {
  zkp_egd_end_time = clock();
  double diff_time = ((double)(zkp_egd_end_time - zkp_egd_start_time)) /CLOCKS_PER_SEC;
  if (str) {
    printf(str);
    printf("%f\n", diff_time);
  }

  return diff_time;
}


zkp_el_gamal_dlog_proof_t *zkp_el_gamal_dlog_new (uint64_t batch_size, ec_group_t ec)
{
  zkp_el_gamal_dlog_proof_t *proof = malloc(sizeof(zkp_el_gamal_dlog_proof_t));
  
  proof->batch_size = batch_size;
  proof->ec = ec;
  proof->V  = gr_el_array_new(batch_size, ec);
  proof->W1 = gr_el_array_new(batch_size, ec);
  proof->W2 = gr_el_array_new(batch_size, ec);
  proof->z  = scalar_array_new(batch_size);
  proof->w  = scalar_array_new(batch_size);

  return proof;
}

void zkp_el_gamal_dlog_copy_anchor (zkp_el_gamal_dlog_proof_t * copy_anchor, zkp_el_gamal_dlog_proof_t * const anchor)
{
  gr_el_array_copy(copy_anchor->V, anchor->V, anchor->batch_size);
  gr_el_array_copy(copy_anchor->W1, anchor->W1, anchor->batch_size);
  gr_el_array_copy(copy_anchor->W2, anchor->W2, anchor->batch_size);
  
  memcpy(copy_anchor->anchor_hash, anchor->anchor_hash, sizeof(hash_chunk));
}

void zkp_el_gamal_dlog_free (zkp_el_gamal_dlog_proof_t *proof)
{
  gr_el_array_free(proof->W1, proof->batch_size);
  gr_el_array_free(proof->W2, proof->batch_size);
  gr_el_array_free(proof->V, proof->batch_size);
  scalar_array_free(proof->z, proof->batch_size);
  scalar_array_free(proof->w, proof->batch_size);
  free(proof);
}

void  zkp_el_gamal_dlog_update_anchor_hash(zkp_el_gamal_dlog_proof_t *partial_proof) {

  uint64_t batch_size = partial_proof->batch_size;
  ec_group_t ec = partial_proof->ec;

  uint8_t *hash_bytes = malloc(GROUP_ELEMENT_BYTES);

  SHA512_CTX anchor_hash_ctx;
  SHA512_Init(&anchor_hash_ctx);

  for (uint64_t i = 0; i < batch_size; ++i) {

    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, partial_proof->V[i], ec, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, partial_proof->W1[i], ec, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, partial_proof->W2[i], ec, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);
  }

  SHA512_Final(partial_proof->anchor_hash, &anchor_hash_ctx);

  free(hash_bytes);
}

void  zkp_el_gamal_dlog_anchor (zkp_el_gamal_dlog_proof_t *partial_proof, zkp_el_gamal_dlog_secret_t *partial_secret, const zkp_el_gamal_dlog_public_t *partial_public)
{
  uint64_t batch_size = partial_public->batch_size;
  ec_group_t ec = partial_public->ec;
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  start_timer();
  for (uint64_t i = 0; i < batch_size; ++i) {

    scalar_sample_in_range(partial_secret->lambda[i], ec_group_order(ec), 0, bn_ctx);
    scalar_sample_in_range(partial_secret->rho[i], ec_group_order(ec), 0, bn_ctx);
 
    // OPTIMIZATION

    EC_POINT_mul(ec, partial_proof->V[i], NULL, partial_public->R[i], partial_secret->rho[i], bn_ctx);
    EC_POINT_mul(ec, partial_proof->W1[i], partial_secret->lambda[i], NULL, NULL, bn_ctx);
    EC_POINT_mul(ec, partial_proof->W2[i], partial_secret->rho[i], partial_public->Y, partial_secret->lambda[i], bn_ctx);
  }

  zkp_el_gamal_dlog_update_anchor_hash(partial_proof);

  BN_CTX_free(bn_ctx);
}

void zkp_el_gamal_dlog_challenge(scalar_t *e, const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  uint64_t batch_size = public->batch_size;

  uint64_t fs_data_len = aux->info_len + (2+4*batch_size)*GROUP_ELEMENT_BYTES + (use_hash ? sizeof(hash_chunk) : 3*batch_size*GROUP_ELEMENT_BYTES);
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->ec, 1);
  
  for (uint64_t i = 0; i < batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B2[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->H[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->R[i], public->ec, 1);
  }
  
  if (use_hash) {
    memcpy(data_pos, proof->anchor_hash, sizeof(hash_chunk));
    data_pos += sizeof(hash_chunk);
  } else {
    for (uint64_t i = 0; i < batch_size; ++i) {
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V[i], public->ec, 1);
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W1[i], public->ec, 1);
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W2[i], public->ec, 1);
    }
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, batch_size, ec_group_order(public->ec), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_el_gamal_dlog_prove (zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_secret_t *secret, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  uint64_t batch_size = public->batch_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t ec_order = ec_group_order(public->ec);
  scalar_t *e = scalar_array_new(batch_size);

  // Assumes anchor was generated already 
  zkp_el_gamal_dlog_challenge(e, proof, public, aux, use_hash);

  for (uint64_t i = 0; i < batch_size; ++i ) {
    BN_mod_mul(proof->z[i], e[i], secret->k[i], ec_order, bn_ctx);
    BN_mod_add(proof->z[i], proof->z[i], secret->rho[i], ec_order, bn_ctx);

    BN_mod_mul(proof->w[i], e[i], secret->b[i], ec_order, bn_ctx);
    BN_mod_add(proof->w[i], proof->w[i], secret->lambda[i], ec_order, bn_ctx);
  }

  scalar_array_free(e, batch_size);
  BN_CTX_free(bn_ctx);
}

int   zkp_el_gamal_dlog_verify (const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = public->batch_size;

  scalar_t  minus_e    = scalar_new();
  scalar_t  *e         = scalar_array_new(batch_size);

  int is_verified = 1;

  zkp_el_gamal_dlog_challenge(e, proof, public, aux, use_hash);
  
  zkp_el_gamal_dlog_proof_t *computed_proof = zkp_el_gamal_dlog_new(batch_size, public->ec);

  for (uint64_t i = 0; i < batch_size; ++i) {
    scalar_negate(minus_e, e[i]);

    group_operation(computed_proof->V[i], NULL, NULL, public->R[i], proof->z[i], public->ec, bn_ctx);
    group_operation(computed_proof->V[i], computed_proof->V[i], NULL, public->H[i], minus_e, public->ec, bn_ctx);

    group_operation(computed_proof->W1[i], NULL, proof->w[i], public->B1[i], minus_e, public->ec, bn_ctx);

    group_operation(computed_proof->W2[i], NULL, proof->z[i], public->Y, proof->w[i], public->ec, bn_ctx);
    group_operation(computed_proof->W2[i], computed_proof->W2[i], NULL, public->B2[i], minus_e, public->ec, bn_ctx);

    if (!use_hash) {
      is_verified &= (group_elem_equal(computed_proof->V[i], proof->V[i], public->ec) == 1);
      is_verified &= (group_elem_equal(computed_proof->W1[i], proof->W1[i], public->ec) == 1);
      is_verified &= (group_elem_equal(computed_proof->W2[i], proof->W2[i], public->ec) == 1);
    }
  }

  if (use_hash) {
    zkp_el_gamal_dlog_update_anchor_hash(computed_proof);
    is_verified &= (memcmp(computed_proof->anchor_hash, proof->anchor_hash, sizeof(hash_chunk)) == 0);
  }
  
  zkp_el_gamal_dlog_free(computed_proof);
  scalar_array_free(e, batch_size);
  scalar_free(minus_e);
  BN_CTX_free(bn_ctx);

  return is_verified;
}

void zkp_el_gamal_dlog_aggregate_anchors (zkp_el_gamal_dlog_proof_t *agg_anchor, zkp_el_gamal_dlog_proof_t ** const anchors, uint64_t num) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = agg_anchor->batch_size;
  ec_group_t ec = agg_anchor->ec;
  
  for (uint64_t i = 0; i < num; ++i) {
    assert(batch_size == anchors[i]->batch_size);
  }

  for (uint64_t l = 0; l < batch_size; ++l) {
    
    group_operation(agg_anchor->V[l], NULL, NULL, NULL, NULL, ec, bn_ctx);
    group_operation(agg_anchor->W1[l], NULL, NULL, NULL, NULL, ec, bn_ctx);
    group_operation(agg_anchor->W2[l], NULL, NULL, NULL, NULL, ec, bn_ctx);
  
    for (uint64_t i = 0; i < num; ++i) {
      
      group_operation(agg_anchor->V[l], agg_anchor->V[l], NULL, anchors[i]->V[l], NULL, ec, bn_ctx);
      group_operation(agg_anchor->W1[l], agg_anchor->W1[l], NULL, anchors[i]->W1[l], NULL, ec, bn_ctx);
      group_operation(agg_anchor->W2[l], agg_anchor->W2[l], NULL, anchors[i]->W2[l], NULL, ec, bn_ctx);
    }   
  }

  zkp_el_gamal_dlog_update_anchor_hash(agg_anchor);

  BN_CTX_free(bn_ctx);
}

void zkp_el_gamal_dlog_aggregate_local_proofs (zkp_el_gamal_dlog_proof_t *agg_proof, zkp_el_gamal_dlog_proof_t ** const local_proofs, uint64_t num) {

  uint64_t batch_size = agg_proof->batch_size;
  ec_group_t ec = agg_proof->ec;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  for (uint64_t i = 0; i < num; ++i) {
    assert(batch_size == local_proofs[i]->batch_size);
  }

  for (uint64_t l = 0; l < batch_size; ++l) {
    
    scalar_set_ul(agg_proof->z[l], 0);
    scalar_set_ul(agg_proof->w[l], 0);
  
    for (uint64_t i = 0; i < num; ++i) {
      assert(group_elem_equal(agg_proof->V[l], local_proofs[i]->V[l], ec) == 1);
      assert(group_elem_equal(agg_proof->W1[l], local_proofs[i]->W1[l], ec) == 1);
      assert(group_elem_equal(agg_proof->W2[l], local_proofs[i]->W2[l], ec) == 1);
     
      scalar_add(agg_proof->z[l], agg_proof->z[l], local_proofs[i]->z[l], ec_group_order(ec), bn_ctx);
      scalar_add(agg_proof->w[l], agg_proof->w[l], local_proofs[i]->w[l], ec_group_order(ec), bn_ctx);
    }   
  }
  
  BN_CTX_free(bn_ctx);
}

uint64_t zkp_el_gamal_dlog_anchor_bytelen   (uint64_t batch_size, int use_hash) {
  return (use_hash ? sizeof(hash_chunk) : 3*batch_size*GROUP_ELEMENT_BYTES);
}

uint64_t zkp_el_gamal_dlog_proof_bytelen(uint64_t batch_size, int use_hash) {
  return 2*batch_size*GROUP_ORDER_BYTES + zkp_el_gamal_dlog_anchor_bytelen(batch_size, use_hash);
}