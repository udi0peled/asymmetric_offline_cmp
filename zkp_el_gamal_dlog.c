#include <openssl/sha.h>
#include "zkp_el_gamal_dlog.h"

zkp_el_gamal_dlog_proof_t *zkp_el_gamal_dlog_new (uint64_t batch_size)
{
  zkp_el_gamal_dlog_proof_t *proof = malloc(sizeof(zkp_el_gamal_dlog_proof_t));
  
  proof->batch_size = batch_size;
  proof->z = calloc(batch_size, sizeof(scalar_t));
  proof->w = calloc(batch_size, sizeof(scalar_t));
  for (uint64_t i = 0; i < batch_size; ++i)
  {
    proof->z[i] = scalar_new();
    proof->w[i] = scalar_new();
  }

  return proof;
}

void zkp_el_gamal_dlog_free (zkp_el_gamal_dlog_proof_t *proof)
{
  for (uint64_t i = 0; i < proof->batch_size; ++i)
  {
    scalar_free(proof->z[i]);
    scalar_free(proof->w[i]);
  }
  free(proof->z);
  free(proof->w);
  free(proof);
}

void  zkp_el_gamal_dlog_anchor (zkp_el_gamal_dlog_proof_t *partial_proof, zkp_el_gamal_dlog_secret_t *partial_secret, const zkp_el_gamal_dlog_public_t *partial_public)
{
  uint64_t batch_size = partial_public->batch_size;

  gr_elem_t curr_gr_elem  = group_elem_new(partial_public->G);

  partial_secret->lambda = calloc(batch_size, sizeof(scalar_t));
  partial_secret->rho = calloc(batch_size, sizeof(scalar_t));
  
  uint8_t *hash_bytes = malloc(GROUP_ELEMENT_BYTES);

  SHA512_CTX anchor_hash_ctx;
  SHA512_Init(&anchor_hash_ctx);

  for (uint64_t i = 0; i < batch_size; ++i) {

    partial_secret->lambda[i] = scalar_new();
    partial_secret->rho[i] = scalar_new();

    scalar_sample_in_range(partial_secret->lambda[i], ec_group_order(partial_public->G), 0);
    scalar_sample_in_range(partial_secret->rho[i], ec_group_order(partial_public->G), 0);

    group_operation(curr_gr_elem, NULL, partial_public->R[i], partial_secret->rho[i], partial_public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_elem, partial_public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_operation(curr_gr_elem, NULL, partial_public->g, partial_secret->lambda[i], partial_public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_elem, partial_public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_operation(curr_gr_elem, NULL, partial_public->Y, partial_secret->lambda[i], partial_public->G);
    group_operation(curr_gr_elem, curr_gr_elem, partial_public->g, partial_secret->rho[i], partial_public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_elem, partial_public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);
  }

  SHA512_Final(partial_proof->anchor_hash, &anchor_hash_ctx);
  free(hash_bytes);
}

void zkp_el_gamal_dlog_challenge(scalar_t *e, const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t fs_data_len = aux->info_len + (2+4*public->batch_size)*GROUP_ELEMENT_BYTES +sizeof(hash_chunk);
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->G, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->G, 1);
  
  for (uint64_t i = 0; i < public->batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B1[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->B2[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->H[i], public->G, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->R[i], public->G, 1);
  }
  
  memcpy(data_pos, proof->anchor_hash, sizeof(hash_chunk));

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, public->batch_size, ec_group_order(public->G), fs_data, fs_data_len);

  free(fs_data);
}

void zkp_el_gamal_dlog_prove (zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_secret_t *secret, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux)
{
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t *e = calloc(public->batch_size, sizeof(scalar_t));
  for (uint64_t i = 0; i < public->batch_size; ++i ) e[i] = scalar_new();

  // Assumes anchor was generated already 
  zkp_el_gamal_dlog_challenge(e, proof, public, aux);

  for (uint64_t i = 0; i < public->batch_size; ++i ) {
    BN_mod_mul(proof->z[i], e[i], secret->k[i], ec_group_order(public->G), bn_ctx);
    BN_mod_add(proof->z[i], proof->z[i], secret->rho[i], ec_group_order(public->G), bn_ctx);

    BN_mod_mul(proof->w[i], e[i], secret->b[i], ec_group_order(public->G), bn_ctx);
    BN_mod_add(proof->w[i], proof->w[i], secret->lambda[i], ec_group_order(public->G), bn_ctx);
  }

  for (uint64_t i = 0; i < public->batch_size; ++i )scalar_free(e[i]);
  free(e);
  BN_CTX_free(bn_ctx);
}

int   zkp_el_gamal_dlog_verify (const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux)
{

  gr_elem_t curr_gr_el = group_elem_new(public->G);
  scalar_t  minus_e    = scalar_new();
  scalar_t  *e         = calloc(public->batch_size, sizeof(scalar_t));
  for (uint64_t i = 0; i < public->batch_size; ++i ) e[i] = scalar_new();

  zkp_el_gamal_dlog_challenge(e, proof, public, aux);

  uint8_t *hash_bytes = malloc(GROUP_ELEMENT_BYTES);
  hash_chunk computed_anchor_hash;

  SHA512_CTX anchor_hash_ctx;
  SHA512_Init(&anchor_hash_ctx);
  
  for (uint64_t i = 0; i < public->batch_size; ++i) {
    scalar_negate(minus_e, e[i]);

    group_operation(curr_gr_el, NULL, public->R[i], proof->z[i], public->G);
    group_operation(curr_gr_el, curr_gr_el, public->H[i], minus_e, public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_el, public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_operation(curr_gr_el, NULL, public->g, proof->w[i], public->G);
    group_operation(curr_gr_el, curr_gr_el, public->B1[i], minus_e, public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_el, public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);

    group_operation(curr_gr_el, NULL, public->Y, proof->w[i], public->G);
    group_operation(curr_gr_el, curr_gr_el, public->g, proof->z[i], public->G);
    group_operation(curr_gr_el, curr_gr_el, public->B2[i], minus_e, public->G);
    group_elem_to_bytes(&hash_bytes, GROUP_ELEMENT_BYTES, curr_gr_el, public->G, 0);
    SHA512_Update(&anchor_hash_ctx, hash_bytes, GROUP_ELEMENT_BYTES);
  }

  SHA512_Final(computed_anchor_hash, &anchor_hash_ctx);

  int is_verified = (memcmp(computed_anchor_hash, proof->anchor_hash, sizeof(hash_chunk)) == 0);
  
  for (uint64_t i = 0; i < public->batch_size; ++i ) scalar_free(e[i]);
  free(e);
  free(hash_bytes);
  group_elem_free(curr_gr_el);
  scalar_free(minus_e);

  return is_verified;
}

uint64_t zkp_el_gamal_dlog_proof_bytelen() {
  return GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;
}

/*
void  zkp_el_gamal_dlog_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_el_gamal_dlog_proof_t *proof, const ec_group_t G, int move_to_snd)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }

  uint8_t *set_bytes = *bytes;
  
  group_elem_to_bytes(&set_bytes, GROUP_ELEMENT_BYTES, proof->A, G, 1);
  scalar_to_bytes(&set_bytes, GROUP_ORDER_BYTES, proof->z, 1);

  assert(set_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = set_bytes;
}

void  zkp_el_gamal_dlog_proof_from_bytes (zkp_el_gamal_dlog_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, const ec_group_t G, int move_to_end)
{
  uint64_t needed_byte_len = GROUP_ELEMENT_BYTES + GROUP_ORDER_BYTES;

  if ((!bytes) || (!*bytes) || (!proof) || (needed_byte_len > *byte_len))
  {
    *byte_len = needed_byte_len;
    return ;
  }
  
  uint8_t *read_bytes = *bytes;
  
  group_elem_from_bytes(proof->A, &read_bytes, GROUP_ELEMENT_BYTES, G, 1);
  scalar_from_bytes(proof->z, &read_bytes, GROUP_ORDER_BYTES, 1);

  assert(read_bytes == *bytes + needed_byte_len);
  *byte_len = needed_byte_len;
  if (move_to_end) *bytes = read_bytes;
}

*/