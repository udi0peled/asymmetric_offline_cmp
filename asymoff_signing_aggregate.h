
#ifndef __ASYMOFF_SIGNING_AGGREGATE_H__
#define __ASYMOFF_SIGNING_AGGREGATE_H__

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "zkp_common.h"
#include "zkp_range_el_gamal_commitment.h"
#include "zkp_el_gamal_dlog.h"
#include "zkp_double_el_gamal.h"
#include "zkp_well_formed_signature.h"
#include "asymoff_protocol.h"

typedef struct
{  
  hash_chunk *T;

} asymoff_sign_agg_msg_round_1_t;

typedef struct
{
  zkp_el_gamal_dlog_proof_t         *pi_eph_anchor;
  zkp_double_el_gamal_proof_t       *pi_chi_anchor;
  zkp_well_formed_signature_proof_t *pi_sig_anchor;
  
  gr_elem_t *V1;
  gr_elem_t *V2;

  scalar_t *packed_Z;
  scalar_t *packed_S;
  gr_elem_t *L1;
  gr_elem_t *L2;
  gr_elem_t *U1;
  gr_elem_t *U2;

  hash_chunk *echo_all_T;
  hash_chunk *u;

} asymoff_sign_agg_msg_round_2_t;

typedef struct
{
  zkp_el_gamal_dlog_proof_t         *pi_eph_local_agg_proof;
  zkp_double_el_gamal_proof_t       *pi_chi_local_agg_proof;
  zkp_well_formed_signature_proof_t *pi_sig_local_agg_proof;

} asymoff_sign_agg_msg_round_3_t;

typedef struct
{
  zkp_el_gamal_dlog_proof_t         *pi_eph_agg_proof;
  zkp_double_el_gamal_proof_t       *pi_chi_agg_proof;
  zkp_well_formed_signature_proof_t *pi_sig_agg_proof;

  gr_elem_t *R;

  gr_elem_t *joint_V1;
  gr_elem_t *joint_V2;

  scalar_t *packed_Z;
  scalar_t *packed_S;

} asymoff_sign_agg_msg_offline_t;

typedef struct 
{
  uint64_t i;
  uint64_t num_parties;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t Y;

  scalar_t x;
  gr_elem_t *X;
  gr_elem_t online_X;

  uint64_t num_sigs;
  
  gr_elem_t *H;
  gr_elem_t **B1;
  gr_elem_t **B2;
  gr_elem_t *V1;
  gr_elem_t *V2;

  gr_elem_t *joint_B1;
  gr_elem_t *joint_B2;
  gr_elem_t *joint_V1;
  gr_elem_t *joint_V2;

  gr_elem_t *R;
  scalar_t *b;
  scalar_t *nonce;
  scalar_t *chi;
  scalar_t *v;

  scalar_t  *msgs;

  hash_chunk T;
  hash_chunk u;
  hash_chunk echo_all_T;

  scalar_t W_0;
  
  scalar_t *signature_sigma;

  zkp_el_gamal_dlog_public_t  pi_eph_agg_public;
  zkp_el_gamal_dlog_proof_t*  pi_eph_local_agg_proof;
  zkp_el_gamal_dlog_proof_t*  pi_eph_agg_proof;
  zkp_el_gamal_dlog_proof_t*  pi_eph_anchor;
  zkp_el_gamal_dlog_secret_t  pi_eph_anchor_secret;

  zkp_double_el_gamal_public_t  pi_chi_agg_public;
  zkp_double_el_gamal_proof_t*  pi_chi_local_agg_proof;
  zkp_double_el_gamal_proof_t*  pi_chi_agg_proof;
  zkp_double_el_gamal_proof_t*  pi_chi_anchor;
  zkp_double_el_gamal_secret_t  pi_chi_anchor_secret;

  zkp_well_formed_signature_public_t  pi_sig_local_public;
  zkp_well_formed_signature_public_t  pi_sig_agg_public;
  zkp_well_formed_signature_proof_t*  pi_sig_local_agg_proof;
  zkp_well_formed_signature_proof_t*  pi_sig_agg_proof;
  zkp_well_formed_signature_proof_t*  pi_sig_anchor;
  zkp_well_formed_signature_secret_t  pi_sig_anchor_secret;
    
  paillier_private_key_t *paillier_offline_priv;
  paillier_public_key_t **paillier_pub;
  ring_pedersen_public_t **rped_pub;

  asymoff_sign_agg_msg_round_1_t *in_aggregate_msg_1;
  asymoff_sign_agg_msg_round_2_t *in_aggregate_msg_2;
  asymoff_sign_agg_msg_round_3_t *in_aggregate_msg_3;
  asymoff_sign_agg_msg_offline_t *in_aggregate_msg_offline;

} asymoff_sign_agg_data_t;

asymoff_sign_agg_data_t **asymoff_signing_aggregate_parties_new(asymoff_party_data_t ** parties, scalar_t *msgs);
void asymoff_signing_aggregate_parties_free(asymoff_sign_agg_data_t **parties);

int asymoff_signing_aggregate_execute_round_1(asymoff_sign_agg_data_t *party);
int asymoff_signing_aggregate_execute_round_2(asymoff_sign_agg_data_t *party);
int asymoff_signing_aggregate_execute_round_3(asymoff_sign_agg_data_t *party);
int asymoff_signing_aggregate_execute_final  (asymoff_sign_agg_data_t *party);

int asymoff_signing_aggregate_execute_offline(asymoff_sign_agg_data_t *party, scalar_t *signatures_s);

uint64_t asymoff_signing_aggregate_send_msg_1(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver);
uint64_t asymoff_signing_aggregate_send_msg_2(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver);
uint64_t asymoff_signing_aggregate_send_msg_3(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver);

uint64_t asymoff_signing_aggregate_send_msg_offline(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver);

#endif