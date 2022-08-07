#include "zkp_schnorr.h"

// Only allocates (and later frees) proof fields, all other are assumed to be populated externally
zkp_schnorr_proof_t *zkp_schnorr_new (const ec_group_t ec)
{
  zkp_schnorr_proof_t *proof = malloc(sizeof(zkp_schnorr_proof_t));
  
  proof->A = group_elem_new(ec);
  proof->z = scalar_new();

  return proof;
}

void  zkp_schnorr_copy_anchor (zkp_schnorr_proof_t *copy_anchor, const zkp_schnorr_proof_t *anchor) {
  group_elem_copy(copy_anchor->A, anchor->A);
}

void zkp_schnorr_free (zkp_schnorr_proof_t *proof)
{
  group_elem_free(proof->A);
  scalar_free(proof->z);
  free(proof);
}

void  zkp_schnorr_anchor (zkp_schnorr_proof_t *partial_proof, zkp_schnorr_secret_t *partial_secret, const zkp_schnorr_public_t *partial_public)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_sample_in_range(partial_secret->a, ec_group_order(partial_public->ec), 0, bn_ctx);
  group_operation(partial_proof->A, NULL, partial_secret->a, NULL, NULL, partial_public->ec, bn_ctx);

  BN_CTX_free(bn_ctx);
}

void zkp_schnoor_challenge(scalar_t *e, const zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + (2 + public->batch_size)*GROUP_ELEMENT_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, ec_group_generator(public->ec), public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A, public->ec, 1);

  for (uint64_t i = 0; i < public->batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->X[i], public->ec, 1);
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, public->batch_size, ec_group_order(public->ec), fs_data, fs_data_len);

  free(fs_data);
}

void  zkp_schnorr_prove (zkp_schnorr_proof_t *proof, const zkp_schnorr_secret_t *secret, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();
  
  scalar_t ec_order = ec_group_order(public->ec);
  scalar_t temp = scalar_new();
  scalar_t *e = scalar_array_new(public->batch_size);

  zkp_schnoor_challenge(e, proof, public, aux);

  BN_copy(proof->z, secret->a);

  for (uint64_t i = 0; i < public->batch_size; ++i) {

    BN_mod_mul(temp, e[i], secret->x[i], ec_order, bn_ctx);
    BN_mod_add(proof->z, proof->z, temp, ec_order, bn_ctx);
  }

  scalar_array_free(e, public->batch_size);
  scalar_free(temp);

  BN_CTX_free(bn_ctx);
}

int   zkp_schnorr_verify (const zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t *e = scalar_array_new(public->batch_size);
  scalar_t *minus_e = scalar_array_new(public->batch_size);

  zkp_schnoor_challenge(e, proof, public, aux);
  
  for (uint64_t i = 0; i < public->batch_size; ++i) scalar_negate(minus_e[i], e[i]);

  zkp_schnorr_proof_t *computed_proof = zkp_schnorr_new(public->ec);
  
  group_multi_oper(computed_proof->A, proof->z, public->X, minus_e, public->batch_size, public->ec, bn_ctx);

  int is_verified = (group_elem_equal(computed_proof->A, proof->A, public->ec) == 1);

  zkp_schnorr_free(computed_proof);
  scalar_array_free(e, public->batch_size);
  scalar_array_free(minus_e, public->batch_size);

  BN_CTX_free(bn_ctx);

  return is_verified;
}

uint64_t zkp_schnorr_proof_bytelen() {
  return GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;
}
