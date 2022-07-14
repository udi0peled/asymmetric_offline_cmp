
#ifndef __ASYMOFF_KEY_GENERATION_H__
#define __ASYMOFF_KEY_GENERATION_H__

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "zkp_common.h"
#include "zkp_ring_pedersen_param.h"
#include "zkp_paillier_blum_modulus.h"
#include "zkp_no_small_factors.h"
#include "zkp_tight_range.h"
#include "zkp_schnorr.h"
#include "asymoff_protocol.h"

typedef struct
{
  hash_chunk *V;

} asymoff_key_gen_msg_round_1_t;

typedef struct
{
  hash_chunk *echo_all_V;
  hash_chunk *srid;
  gr_elem_t X;
  gr_elem_t Y;
  gr_elem_t A;
  paillier_public_key_t *paillier_pub;
  ring_pedersen_public_t *rped_pub;
  hash_chunk *u;

} asymoff_key_gen_msg_round_2_t;

typedef struct
{
  zkp_schnorr_proof_t *psi_sch;
  zkp_paillier_blum_modulus_proof_t *psi_paillier;
  zkp_ring_pedersen_param_proof_t *psi_rped;

} asymoff_key_gen_msg_round_3_t;


typedef struct
{
  zkp_no_small_factors_t *psi_factors;

  // From offline party
  zkp_tight_range_proof_t *pi_tight;
  scalar_t W_0;

} asymoff_key_gen_msg_round_4_t;

typedef struct 
{
  hash_chunk sid;
  uint64_t i;
  uint64_t num_parties;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t gen;

  scalar_t  x;
  gr_elem_t X;

  scalar_t y;
  gr_elem_t Y;
  
  scalar_t tau;
  gr_elem_t A;

  hash_chunk srid;

  paillier_private_key_t *paillier_priv;
  paillier_public_key_t *paillier_pub;

  ring_pedersen_private_t *rped_priv;
  ring_pedersen_public_t *rped_pub;
  
  hash_chunk u;
  hash_chunk V;
  hash_chunk echo_all_V;

  hash_chunk joint_srid;

  zkp_schnorr_proof_t *psi_sch;
  zkp_paillier_blum_modulus_proof_t *psi_paillier;
  zkp_ring_pedersen_param_proof_t *psi_rped;
  zkp_no_small_factors_t **psi_factors;

  // Array of in coming messages from other parties
  asymoff_key_gen_msg_round_1_t *in_msg_1;
  asymoff_key_gen_msg_round_2_t *in_msg_2;
  asymoff_key_gen_msg_round_3_t *in_msg_3;
  asymoff_key_gen_msg_round_4_t *in_msg_4;

  // The following is generated only by offline party 0
  scalar_t W_0;
  zkp_tight_range_proof_t **pi_tight;

} asymoff_key_gen_data_t;

asymoff_key_gen_data_t **asymoff_key_gen_parties_new(asymoff_party_data_t **parties);
void asymoff_key_gen_parties_free(asymoff_key_gen_data_t **parties);

int asymoff_key_gen_compute_round_1(asymoff_key_gen_data_t *party);
int asymoff_key_gen_compute_round_2(asymoff_key_gen_data_t *party);
int asymoff_key_gen_compute_round_3(asymoff_key_gen_data_t *party);
int asymoff_key_gen_compute_round_4(asymoff_key_gen_data_t *party);
int asymoff_key_gen_compute_final (asymoff_key_gen_data_t *party);

uint64_t asymoff_key_gen_send_msg_1(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver);
uint64_t asymoff_key_gen_send_msg_2(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver);
uint64_t asymoff_key_gen_send_msg_3(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver);
uint64_t asymoff_key_gen_send_msg_4(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver);

void asymoff_key_gen_export_data(asymoff_party_data_t **parties, asymoff_key_gen_data_t **kgd_parties);
void asymoff_key_gen_mock_export_data(asymoff_party_data_t **parties);

#endif