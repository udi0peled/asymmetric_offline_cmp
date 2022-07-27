#include <openssl/sha.h>
#include "zkp_well_formed_signature.h"

#define SOUNDNESS_L 256
#define SLACKNESS_EPS (SOUNDNESS_L + 64)

zkp_well_formed_signature_proof_t *zkp_well_formed_signature_new (ec_group_t ec)
{
  zkp_well_formed_signature_proof_t *proof = malloc(sizeof(zkp_well_formed_signature_proof_t));
  
  proof->ec = ec;
  
  proof->V = scalar_new();
  proof->T = scalar_new();
  proof->d = scalar_new();
  proof->w = scalar_new();

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    proof->A1[p] = group_elem_new(ec);
    proof->A2[p] = group_elem_new(ec);
    proof->B1[p] = group_elem_new(ec);
    proof->B2[p] = group_elem_new(ec);

    proof->z_LB[p]     = scalar_new();
    proof->z_UA[p]     = scalar_new();
    proof->sigma_LB[p] = scalar_new();
    proof->sigma_UA[p] = scalar_new();
  }

  return proof;
}

void zkp_well_formed_signature_copy(zkp_well_formed_signature_proof_t * copy_proof, zkp_well_formed_signature_proof_t * const proof)
{
  scalar_copy(copy_proof->V, proof->V);
  scalar_copy(copy_proof->T, proof->T);
  scalar_copy(copy_proof->d, proof->d);
  scalar_copy(copy_proof->w, proof->w);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    group_elem_copy(copy_proof->A1[p], proof->A1[p]);
    group_elem_copy(copy_proof->A2[p], proof->A2[p]);
    group_elem_copy(copy_proof->B1[p], proof->B1[p]);
    group_elem_copy(copy_proof->B2[p], proof->B2[p]);

    scalar_copy(copy_proof->z_LB[p], proof->z_LB[p]);
    scalar_copy(copy_proof->z_UA[p], proof->z_UA[p]);
    scalar_copy(copy_proof->sigma_LB[p], proof->sigma_LB[p]);
    scalar_copy(copy_proof->sigma_UA[p], proof->sigma_UA[p]);
  }
}

void zkp_well_formed_signature_free (zkp_well_formed_signature_proof_t *proof)
{
  scalar_free(proof->V);
  scalar_free(proof->T);
  scalar_free(proof->d);
  scalar_free(proof->w);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    group_elem_free(proof->A1[p]);
    group_elem_free(proof->A2[p]);
    group_elem_free(proof->B1[p]);
    group_elem_free(proof->B2[p]);

    scalar_free(proof->z_LB[p]);
    scalar_free(proof->z_UA[p]);
    scalar_free(proof->sigma_LB[p]);
    scalar_free(proof->sigma_UA[p]);
  }

  free(proof);
}

void  zkp_well_formed_signature_anchor (zkp_well_formed_signature_proof_t *partial_proof, zkp_well_formed_signature_secret_t *partial_secret, const zkp_well_formed_signature_public_t *partial_public)
{
  assert(2*PACKING_SIZE <= RING_PEDERSEN_MULTIPLICITY);

  ec_group_t ec = partial_public->ec;

  scalar_t temp = scalar_new();
  scalar_t packed = scalar_new();

  scalar_set_power_of_2(temp, SOUNDNESS_L + 2*SLACKNESS_EPS);
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    scalar_sample_in_range(partial_secret->alpha[p], temp, 0);
  }

  
  scalar_set_power_of_2(temp, SOUNDNESS_L + SLACKNESS_EPS);
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) scalar_sample_in_range(partial_secret->beta[p], temp, 0);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    scalar_sample_in_range(partial_secret->delta_UA[p], ec_group_order(ec), 0);
    scalar_sample_in_range(partial_secret->delta_LB[p], ec_group_order(ec), 0);
  }

  BN_lshift(temp, partial_public->rped_pub->N, SLACKNESS_EPS);
  scalar_sample_in_range(partial_secret->nu, temp, 0);

  paillier_encryption_sample(partial_secret->r, partial_public->paillier_pub);

  pack_plaintexts(packed, partial_secret->alpha, NULL, 0);
  paillier_encryption_encrypt(partial_proof->V, packed, partial_secret->r, partial_public->paillier_pub);
  pack_plaintexts(packed, partial_secret->beta, NULL, 0);
  paillier_encryption_homomorphic(partial_proof->V, partial_public->W, packed, partial_proof->V, partial_public->paillier_pub);

  scalar_t rped_s_exps[2*PACKING_SIZE];
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    rped_s_exps[p]                = partial_secret->alpha[p];
    rped_s_exps[PACKING_SIZE + p] = partial_secret->beta[p];
  }
  ring_pedersen_commit(partial_proof->T, rped_s_exps, 2*PACKING_SIZE, partial_secret->nu, partial_public->rped_pub);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    group_operation(partial_proof->A1[p], NULL, partial_public->g, partial_secret->delta_UA[p], ec);

    group_operation(partial_proof->A2[p], NULL, partial_public->g, partial_secret->alpha[p], ec);
    group_operation(partial_proof->A2[p], partial_proof->A2[p], partial_public->Y, partial_secret->delta_UA[p], ec);

    group_operation(partial_proof->B1[p], NULL, partial_public->g, partial_secret->delta_LB[p], ec);

    group_operation(partial_proof->B2[p], NULL, partial_public->g, partial_secret->beta[p], ec);
    group_operation(partial_proof->B2[p], partial_proof->B2[p], partial_public->Y, partial_secret->delta_LB[p], ec);
  }

  scalar_free(temp);
}

void zkp_well_formed_signature_challenge(scalar_t *e, const zkp_well_formed_signature_proof_t *proof, const zkp_well_formed_signature_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = public->batch_size;

  uint64_t fs_data_len = aux->info_len + (2 + 4*batch_size + 4*PACKING_SIZE) * GROUP_ELEMENT_BYTES + (5 + 2*(batch_size/PACKING_SIZE)) * PAILLIER_MODULUS_BYTES + (3 + 2*PACKING_SIZE + (batch_size/PACKING_SIZE)) * RING_PED_MODULUS_BYTES;
  uint8_t *fs_data = malloc(fs_data_len);
  uint8_t *data_pos = fs_data;

  memcpy(data_pos, aux->info, aux->info_len);
  data_pos += aux->info_len;

  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->g, public->ec, 1);
  group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->Y, public->ec, 1);
  
  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->W, 1);

  scalar_to_bytes(&data_pos, PAILLIER_MODULUS_BYTES , public->paillier_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->N, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->t, 1);

  for (uint64_t p = 0; p < 2*PACKING_SIZE; ++p) {
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES , public->rped_pub->s[p], 1);
  }

  for (uint64_t i = 0; i < batch_size/PACKING_SIZE; ++i) {
    scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, public->packed_Z[i], 1);
    scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES,   public->packed_S[i], 1);
  }

  for (uint64_t i = 0; i < batch_size; ++i) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->L1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->L2[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->U1[i], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, public->U2[i], public->ec, 1);
  }

  scalar_to_bytes(&data_pos, 2*PAILLIER_MODULUS_BYTES, proof->V, 1);
  scalar_to_bytes(&data_pos, RING_PED_MODULUS_BYTES,   proof->T, 1);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A1[p], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->A2[p], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->B1[p], public->ec, 1);
    group_elem_to_bytes(&data_pos, GROUP_ELEMENT_BYTES, proof->B2[p], public->ec, 1);
  }

  assert(fs_data + fs_data_len == data_pos);

  fiat_shamir_scalars_in_range(e, batch_size/PACKING_SIZE, ec_group_order(public->ec), fs_data, fs_data_len);
  
  for (uint64_t i = 0; i < public->batch_size/PACKING_SIZE; ++i) scalar_make_signed(e[i], ec_group_order(public->ec));

  free(fs_data);
}

void zkp_well_formed_signature_prove (zkp_well_formed_signature_proof_t *proof, const zkp_well_formed_signature_secret_t *secret, const zkp_well_formed_signature_public_t *public, const zkp_aux_info_t *aux)
{
  uint64_t batch_size = public->batch_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t ec_order = ec_group_order(public->ec);
  scalar_t temp     = scalar_new();
  scalar_t *e       = new_scalar_array(batch_size/PACKING_SIZE);

  // Assumes anchor was generated already 
  zkp_well_formed_signature_challenge(e, proof, public, aux);

  BN_copy(proof->d, secret->r);
  BN_copy(proof->w, secret->nu);

  for (uint64_t i = 0; i < batch_size/PACKING_SIZE; ++i) {

    scalar_exp(temp, secret->rho[i], e[i], public->paillier_pub->N);
    BN_mod_mul(proof->d, proof->d, temp, public->paillier_pub->N, bn_ctx);

    BN_mul(temp, secret->lambda[i], e[i], bn_ctx);
    BN_add(proof->w, proof->w, temp);
  }

  // TODO: most calculations are not modulo (impossible)?

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    BN_copy(proof->z_UA[p], secret->alpha[p]);
    BN_copy(proof->z_LB[p], secret->beta[p]);
    BN_copy(proof->sigma_UA[p], secret->delta_UA[p]);
    BN_copy(proof->sigma_LB[p], secret->delta_LB[p]);


    for (uint64_t i = 0; i < batch_size/PACKING_SIZE; ++i) {

      BN_mul(temp, e[i], secret->mu[PACKING_SIZE*i + p], bn_ctx);
      BN_add(proof->z_UA[p], proof->z_UA[p], temp);

      BN_mul(temp, e[i], secret->xi[PACKING_SIZE*i + p], bn_ctx);
      BN_add(proof->z_LB[p], proof->z_LB[p], temp);

      BN_mod_mul(temp, e[i], secret->gamma_LB[PACKING_SIZE*i + p], ec_order, bn_ctx);
      BN_mod_add(proof->sigma_LB[p], proof->sigma_LB[p], temp, ec_order, bn_ctx);

      BN_mod_mul(temp, e[i], secret->gamma_UA[PACKING_SIZE*i + p], ec_order, bn_ctx);
      BN_mod_add(proof->sigma_UA[p], proof->sigma_UA[p], temp, ec_order, bn_ctx);
    }
  }

  free(temp);
  free_scalar_array(e, batch_size/PACKING_SIZE);
  BN_CTX_free(bn_ctx);
}

int   zkp_well_formed_signature_verify (const zkp_well_formed_signature_proof_t *proof, const zkp_well_formed_signature_public_t *public, const zkp_aux_info_t *aux, int agg_range_slack)
{
  uint64_t batch_size = public->batch_size;
  ec_group_t ec = public->ec;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t  minus_e = scalar_new();
  scalar_t  packed  = scalar_new();
  scalar_t  temp    = scalar_new();
  scalar_t  *e      = new_scalar_array(batch_size/PACKING_SIZE);

  int is_verified = 1;
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    is_verified &= ( BN_num_bits(proof->z_UA[p]) <= SOUNDNESS_L + 2*SLACKNESS_EPS + agg_range_slack);
    is_verified &= ( BN_num_bits(proof->z_LB[p]) <= SOUNDNESS_L + SLACKNESS_EPS + agg_range_slack);
  }

  zkp_well_formed_signature_challenge(e, proof, public, aux);
  
  zkp_well_formed_signature_proof_t *computed_proof = zkp_well_formed_signature_new(ec);

  pack_plaintexts(packed, proof->z_UA, NULL, 0);
  paillier_encryption_encrypt(computed_proof->V, packed, proof->d, public->paillier_pub);

  pack_plaintexts(packed, proof->z_LB, NULL, 0);
  paillier_encryption_homomorphic(computed_proof->V, public->W, packed, computed_proof->V, public->paillier_pub);

  scalar_t rped_s_exps[2*PACKING_SIZE];
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    rped_s_exps[p]                = proof->z_UA[p];
    rped_s_exps[PACKING_SIZE + p] = proof->z_LB[p];
  }
  ring_pedersen_commit(computed_proof->T, rped_s_exps, 2*PACKING_SIZE, proof->w, public->rped_pub);


  // TODO: check co-prime before exp with negative exponenet?

  for (uint64_t i = 0; i < batch_size/PACKING_SIZE; ++i) {
    scalar_negate(minus_e, e[i]);

    paillier_encryption_homomorphic(computed_proof->V, public->packed_Z[i], minus_e, computed_proof->V, public->paillier_pub);
    
    scalar_exp(temp, public->packed_S[i], minus_e, public->rped_pub->N);
    BN_mod_mul(computed_proof->T, computed_proof->T, temp, public->rped_pub->N, bn_ctx);
  }

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    group_operation(computed_proof->A1[p], NULL, public->g, proof->sigma_UA[p], ec);

    group_operation(computed_proof->A2[p], NULL, public->g, proof->z_UA[p], ec);
    group_operation(computed_proof->A2[p], computed_proof->A2[p], public->Y, proof->sigma_UA[p], ec);

    group_operation(computed_proof->B1[p], NULL, public->g, proof->sigma_LB[p], ec);

    group_operation(computed_proof->B2[p], NULL, public->g, proof->z_LB[p], ec);
    group_operation(computed_proof->B2[p], computed_proof->B2[p], public->Y, proof->sigma_LB[p], ec);

    for (uint64_t i = 0; i < batch_size/PACKING_SIZE; ++i) {
      scalar_negate(minus_e, e[i]);

      group_operation(computed_proof->A1[p], computed_proof->A1[p], public->U1[PACKING_SIZE*i + p], minus_e, ec);
      group_operation(computed_proof->A2[p], computed_proof->A2[p], public->U2[PACKING_SIZE*i + p], minus_e, ec);
      group_operation(computed_proof->B1[p], computed_proof->B1[p], public->L1[PACKING_SIZE*i + p], minus_e, ec);
      group_operation(computed_proof->B2[p], computed_proof->B2[p], public->L2[PACKING_SIZE*i + p], minus_e, ec);
    }
  }

  is_verified &= (scalar_equal(computed_proof->V, proof->V) == 1);
  is_verified &= (scalar_equal(computed_proof->T, proof->T) == 1);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    is_verified &= (group_elem_equal(computed_proof->A1[p], proof->A1[p], ec) == 1);
    is_verified &= (group_elem_equal(computed_proof->A2[p], proof->A2[p], ec) == 1);
    is_verified &= (group_elem_equal(computed_proof->B1[p], proof->B1[p], ec) == 1);
    is_verified &= (group_elem_equal(computed_proof->B2[p], proof->B2[p], ec) == 1);
  }
  
  zkp_well_formed_signature_free(computed_proof);
  free_scalar_array(e, batch_size/PACKING_SIZE);
  scalar_free(minus_e);
  scalar_free(packed);
  scalar_free(temp);  

  BN_CTX_free(bn_ctx);

  return is_verified;
}


void zkp_well_formed_signature_aggregate_anchors (zkp_well_formed_signature_proof_t *agg_anchor, zkp_well_formed_signature_proof_t ** const anchors, uint64_t num, const paillier_public_key_t *paillier_pub, const ring_pedersen_public_t *rped_pub) {

  ec_group_t ec = agg_anchor->ec;

  scalar_set_ul(agg_anchor->V, 1);
  scalar_set_ul(agg_anchor->T, 1);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
    group_operation(agg_anchor->A1[p], NULL, NULL, NULL, ec);
    group_operation(agg_anchor->A2[p], NULL, NULL, NULL, ec);
    group_operation(agg_anchor->B1[p], NULL, NULL, NULL, ec);
    group_operation(agg_anchor->B2[p], NULL, NULL, NULL, ec);
  }

  for (uint64_t i = 0; i < num; ++i) {
    
    paillier_encryption_homomorphic(agg_anchor->V, agg_anchor->V, NULL, anchors[i]->V, paillier_pub);
    scalar_mul(agg_anchor->T, agg_anchor->T, anchors[i]->T, rped_pub->N);

    for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

      group_operation(agg_anchor->A1[p], agg_anchor->A1[p], anchors[i]->A1[p], NULL, ec);
      group_operation(agg_anchor->A2[p], agg_anchor->A2[p], anchors[i]->A2[p], NULL, ec);
      group_operation(agg_anchor->B1[p], agg_anchor->B1[p], anchors[i]->B1[p], NULL, ec);
      group_operation(agg_anchor->B2[p], agg_anchor->B2[p], anchors[i]->B2[p], NULL, ec);
    }
  }   
}

void zkp_well_formed_signature_aggregate_local_proofs (zkp_well_formed_signature_proof_t *agg_proof, zkp_well_formed_signature_proof_t ** const local_proofs, uint64_t num, const paillier_public_key_t *paillier_pub) {

  ec_group_t ec = agg_proof->ec;
  scalar_t ec_order = ec_group_order(ec);
  
  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    scalar_set_ul(agg_proof->z_UA[p], 0);
    scalar_set_ul(agg_proof->z_LB[p], 0);
    scalar_set_ul(agg_proof->sigma_UA[p], 0);
    scalar_set_ul(agg_proof->sigma_LB[p], 0);

    scalar_set_ul(agg_proof->w, 0);
    scalar_set_ul(agg_proof->d, 1);
  }

  for (uint64_t i = 0; i < num; ++i) {
    
    assert( scalar_equal(agg_proof->V, local_proofs[i]->V) == 1 );
    assert( scalar_equal(agg_proof->T, local_proofs[i]->T) == 1 );

    BN_add(agg_proof->w, agg_proof->w, local_proofs[i]->w);
    scalar_mul(agg_proof->d, agg_proof->d, local_proofs[i]->d, paillier_pub->N);

    for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

      assert(group_elem_equal(agg_proof->A1[p], local_proofs[i]->A1[p], ec) == 1);
      assert(group_elem_equal(agg_proof->A2[p], local_proofs[i]->A2[p], ec) == 1);
      assert(group_elem_equal(agg_proof->B1[p], local_proofs[i]->B1[p], ec) == 1);
      assert(group_elem_equal(agg_proof->B2[p], local_proofs[i]->B2[p], ec) == 1);
    
      BN_add(agg_proof->z_UA[p], agg_proof->z_UA[p], local_proofs[i]->z_UA[p]);
      BN_add(agg_proof->z_LB[p], agg_proof->z_LB[p], local_proofs[i]->z_LB[p]);

      scalar_add(agg_proof->sigma_UA[p], agg_proof->sigma_UA[p], local_proofs[i]->sigma_UA[p], ec_order);
      scalar_add(agg_proof->sigma_LB[p], agg_proof->sigma_LB[p], local_proofs[i]->sigma_LB[p], ec_order);
    }
  }   
}

uint64_t zkp_well_formed_signature_proof_bytelen() {
  return 3*PAILLIER_MODULUS_BYTES + 4*GROUP_ELEMENT_BYTES + 2*PACKING_SIZE*GROUP_ORDER_BYTES + 2*RING_PED_MODULUS_BYTES + SLACKNESS_EPS + PACKING_SIZE*(2*SOUNDNESS_L + 3*SLACKNESS_EPS) ;
}