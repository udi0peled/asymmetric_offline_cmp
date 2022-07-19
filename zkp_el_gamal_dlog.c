#include <openssl/sha.h>
#include "zkp_el_gamal_dlog.h"

zkp_el_gamal_dlog_proof_t *zkp_el_gamal_dlog_new (uint64_t batch_size, ec_group_t ec)
{
  zkp_el_gamal_dlog_proof_t *proof = malloc(sizeof(zkp_el_gamal_dlog_proof_t));
  
  proof->batch_size = batch_size;
  proof->ec = ec;
  proof->V  = new_gr_el_array(batch_size, ec);
  proof->W1 = new_gr_el_array(batch_size, ec);
  proof->W2 = new_gr_el_array(batch_size, ec);
  proof->z  = new_scalar_array(batch_size);
  proof->w  = new_scalar_array(batch_size);

  return proof;
}

zkp_el_gamal_dlog_proof_t *zkp_el_gamal_dlog_duplicate (zkp_el_gamal_dlog_proof_t * const proof)
{
  zkp_el_gamal_dlog_proof_t *new_proof = zkp_el_gamal_dlog_new(proof->batch_size, proof->ec);
  
  copy_gr_el_array(new_proof->V, proof->V, proof->batch_size);
  copy_gr_el_array(new_proof->W1, proof->W1, proof->batch_size);
  copy_gr_el_array(new_proof->W2, proof->W2, proof->batch_size);
  copy_scalar_array(new_proof->z, proof->z, proof->batch_size);
  copy_scalar_array(new_proof->w, proof->w, proof->batch_size);

  return new_proof;
}

void zkp_el_gamal_dlog_free (zkp_el_gamal_dlog_proof_t *proof)
{
  free_gr_el_array(proof->W1, proof->batch_size);
  free_gr_el_array(proof->W2, proof->batch_size);
  free_gr_el_array(proof->V, proof->batch_size);
  free_scalar_array(proof->z, proof->batch_size);
  free_scalar_array(proof->w, proof->batch_size);
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

  for (uint64_t i = 0; i < batch_size; ++i) {

    scalar_sample_in_range(partial_secret->lambda[i], ec_group_order(partial_public->G), 0);
    scalar_sample_in_range(partial_secret->rho[i], ec_group_order(partial_public->G), 0);

    group_operation(partial_proof->V[i], NULL, partial_public->R[i], partial_secret->rho[i], partial_public->G);

    group_operation(partial_proof->W1[i], NULL, partial_public->g, partial_secret->lambda[i], partial_public->G);

    group_operation(partial_proof->W2[i], NULL, partial_public->Y, partial_secret->lambda[i], partial_public->G);
    group_operation(partial_proof->W2[i], partial_proof->W2[i], partial_public->g, partial_secret->rho[i], partial_public->G);
  }

  zkp_el_gamal_dlog_update_anchor_hash(partial_proof);
}

void zkp_el_gamal_dlog_challenge(scalar_t *e, const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  uint64_t batch_size = public->batch_size;

  uint64_t fs_data_len = aux->info_len + (2+4*batch_size)*GROUP_ELEMENT_BYTES + (use_hash ? sizeof(hash_chunk) : 3*batch_size*GROUP_ELEMENT_BYTES);
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->G, 1);
  
  for (uint64_t i = 0; i < batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B1[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B2[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->H[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->R[i], public->G, 1);
  }
  
  if (use_hash) {
    memcpy(data_pos, proof->anchor_hash, sizeof(hash_chunk));
    data_pos += sizeof(hash_chunk);
  } else {
    for (uint64_t i = 0; i < batch_size; ++i) {
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->V[i], public->G, 1);
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W1[i], public->G, 1);
      group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->W2[i], public->G, 1);
    }
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, batch_size, ec_group_order(public->G), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_el_gamal_dlog_prove (zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_secret_t *secret, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  uint64_t batch_size = public->batch_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();
  scalar_t *e = new_scalar_array(batch_size);

  // Assumes anchor was generated already 
  zkp_el_gamal_dlog_challenge(e, proof, public, aux, use_hash);

  for (uint64_t i = 0; i < batch_size; ++i ) {
    BN_mod_mul(proof->z[i], e[i], secret->k[i], ec_group_order(public->G), bn_ctx);
    BN_mod_add(proof->z[i], proof->z[i], secret->rho[i], ec_group_order(public->G), bn_ctx);

    BN_mod_mul(proof->w[i], e[i], secret->b[i], ec_group_order(public->G), bn_ctx);
    BN_mod_add(proof->w[i], proof->w[i], secret->lambda[i], ec_group_order(public->G), bn_ctx);
  }

  free_scalar_array(e, batch_size);
  BN_CTX_free(bn_ctx);
}

int   zkp_el_gamal_dlog_verify (const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash)
{
  uint64_t batch_size = public->batch_size;

  scalar_t  minus_e    = scalar_new();
  scalar_t  *e         = new_scalar_array(batch_size);

  int is_verified = 1;

  zkp_el_gamal_dlog_challenge(e, proof, public, aux, use_hash);
  
  zkp_el_gamal_dlog_proof_t *computed_proof = zkp_el_gamal_dlog_new(batch_size, public->G);

  for (uint64_t i = 0; i < batch_size; ++i) {
    scalar_negate(minus_e, e[i]);

    group_operation(computed_proof->V[i], NULL, public->R[i], proof->z[i], public->G);
    group_operation(computed_proof->V[i], computed_proof->V[i], public->H[i], minus_e, public->G);

    group_operation(computed_proof->W1[i], NULL, public->g, proof->w[i], public->G);
    group_operation(computed_proof->W1[i], computed_proof->W1[i], public->B1[i], minus_e, public->G);

    group_operation(computed_proof->W2[i], NULL, public->Y, proof->w[i], public->G);
    group_operation(computed_proof->W2[i], computed_proof->W2[i], public->g, proof->z[i], public->G);
    group_operation(computed_proof->W2[i], computed_proof->W2[i], public->B2[i], minus_e, public->G);

    if (!use_hash) {
      is_verified &= (group_elem_equal(computed_proof->V[i], proof->V[i], public->G) == 1);
      is_verified &= (group_elem_equal(computed_proof->W1[i], proof->W1[i], public->G) == 1);
      is_verified &= (group_elem_equal(computed_proof->W2[i], proof->W2[i], public->G) == 1);
    }
  }

  if (use_hash) {
    zkp_el_gamal_dlog_update_anchor_hash(computed_proof);
    is_verified &= (memcmp(computed_proof->anchor_hash, proof->anchor_hash, sizeof(hash_chunk)) == 0);
  }
  
  zkp_el_gamal_dlog_free(computed_proof);
  free_scalar_array(e, batch_size);
  scalar_free(minus_e);

  return is_verified;
}


void zkp_el_gamal_dlog_aggregate_public (zkp_el_gamal_dlog_public_t *agg_public, zkp_el_gamal_dlog_public_t ** const publics, uint64_t num) {

  uint64_t batch_size = agg_public->batch_size;
  
  ec_group_t ec = agg_public->G;

  for (uint64_t i = 0; i < num; ++i) {

    assert(batch_size == publics[i]->batch_size);

    assert(group_elem_equal(agg_public->g, publics[i]->g, ec) == 1);
    assert(group_elem_equal(agg_public->Y, publics[i]->Y, ec) == 1);
  }

  for (uint64_t l = 0; l < batch_size; ++l) {
    
    // group_elem_copy(agg_public->H[l], publics[0]->H[l]);
    // group_elem_copy(agg_public->R[l], publics[0]->R[l]);

    group_operation(agg_public->B1[l], NULL, NULL, NULL, ec);
    group_operation(agg_public->B2[l], NULL, NULL, NULL, ec);
  
    for (uint64_t i = 0; i < num; ++i) {
      
      assert(group_elem_equal(agg_public->H[l], publics[i]->H[l], ec) == 1);
      assert(group_elem_equal(agg_public->R[l], publics[i]->R[l], ec) == 1);

      group_operation(agg_public->B1[l], agg_public->B1[l], publics[i]->B1[l], NULL, ec);
      group_operation(agg_public->B2[l], agg_public->B2[l], publics[i]->B2[l], NULL, ec);
    }   
  }
}

void zkp_el_gamal_dlog_aggregate_anchors (zkp_el_gamal_dlog_proof_t *agg_anchor, zkp_el_gamal_dlog_proof_t ** const anchors, uint64_t num) {

  uint64_t batch_size = agg_anchor->batch_size;
  ec_group_t ec = agg_anchor->ec;
  
  for (uint64_t i = 0; i < num; ++i) {
    assert(batch_size == anchors[i]->batch_size);
  }

  for (uint64_t l = 0; l < batch_size; ++l) {
    
    group_operation(agg_anchor->V[l], NULL, NULL, NULL, ec);
    group_operation(agg_anchor->W1[l], NULL, NULL, NULL, ec);
    group_operation(agg_anchor->W2[l], NULL, NULL, NULL, ec);
  
    for (uint64_t i = 0; i < num; ++i) {
      
      group_operation(agg_anchor->V[l], agg_anchor->V[l], anchors[i]->V[l], NULL, ec);
      group_operation(agg_anchor->W1[l], agg_anchor->W1[l], anchors[i]->W1[l], NULL, ec);
      group_operation(agg_anchor->W2[l], agg_anchor->W2[l], anchors[i]->W2[l], NULL, ec);
    }   
  }

  zkp_el_gamal_dlog_update_anchor_hash(agg_anchor);
}

void zkp_el_gamal_dlog_aggregate_local_proofs (zkp_el_gamal_dlog_proof_t *agg_proof, zkp_el_gamal_dlog_proof_t ** const local_proofs, uint64_t num) {

  uint64_t batch_size = agg_proof->batch_size;
  ec_group_t ec = agg_proof->ec;
  
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
     
      scalar_add(agg_proof->z[l], agg_proof->z[l], local_proofs[i]->z[l], ec_group_order(ec));
      scalar_add(agg_proof->w[l], agg_proof->w[l], local_proofs[i]->w[l], ec_group_order(ec));
    }   
  }
}

uint64_t zkp_el_gamal_dlog_proof_bytelen(uint64_t batch_size, int use_hash) {
  return 2*batch_size*GROUP_ORDER_BYTES + (use_hash ? sizeof(hash_chunk) : 3*batch_size*GROUP_ELEMENT_BYTES);
}