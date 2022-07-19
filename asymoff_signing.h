
#ifndef __ASYMOFF_SIGNING_H__
#define __ASYMOFF_SIGNING_H__


#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "zkp_common.h"
#include "zkp_range_el_gamal_commitment.h"
#include "zkp_el_gamal_dlog.h"
#include "asymoff_protocol.h"

typedef struct
{
} asymoff_signing_online_msg_round_1_t;

typedef struct
{
} asymoff_signing_online_msg_round_2_t;

typedef struct
{
} asymoff_signing_online_msg_round_3_t;

typedef struct
{
} asymoff_signing_online_msg_round_4_t;

typedef struct
{  
  hash_chunk *T;
} asymoff_signing_aggregate_msg_round_1_t;

typedef struct
{
  hash_chunk *echo_all_T;
  zkp_el_gamal_dlog_proof_t *pi_eph_anchor;

  hash_chunk *u;
} asymoff_signing_aggregate_msg_round_2_t;

typedef struct
{
  zkp_el_gamal_dlog_proof_t *pi_eph_local_proof;
} asymoff_signing_aggregate_msg_round_3_t;

typedef struct {

} asymoff_signing_online_t;

typedef struct {

} asymoff_signing_offline_t;

typedef struct 
{
  uint64_t i;
  uint64_t num_parties;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t gen;
  gr_elem_t Y;

  scalar_t secret_x;

  uint64_t num_sigs;
  
  gr_elem_t **B1;
  gr_elem_t **B2;
  gr_elem_t *H;

  gr_elem_t *R;
  scalar_t *b;
  scalar_t *nonce;
  scalar_t *chi;

  hash_chunk T;
  hash_chunk u;
  hash_chunk echo_all_T;

  scalar_t W_0;

  zkp_el_gamal_dlog_public_t pi_eph_agg_public;
  zkp_el_gamal_dlog_proof_t *pi_eph_local_agg_proof;
  zkp_el_gamal_dlog_proof_t *pi_eph_anchor;
  zkp_el_gamal_dlog_secret_t pi_eph_anchor_secret;
  
  scalar_t *pi_eph_B_dprime;
  
  paillier_public_key_t **paillier_pub;
  ring_pedersen_public_t **rped_pub;
  
  // Array of in coming messages from other parties
  asymoff_signing_online_msg_round_1_t *in_online_msg_1;
  asymoff_signing_online_msg_round_2_t *in_online_msg_2;
  asymoff_signing_online_msg_round_3_t *in_online_msg_3;
  asymoff_signing_online_msg_round_4_t *in_online_msg_4;

  asymoff_signing_aggregate_msg_round_1_t *in_aggregate_msg_1;
  asymoff_signing_aggregate_msg_round_2_t *in_aggregate_msg_2;
  asymoff_signing_aggregate_msg_round_3_t *in_aggregate_msg_3;

} asymoff_signing_data_t;

asymoff_signing_data_t **asymoff_signing_parties_new(asymoff_party_data_t ** parties, uint64_t sign_amount);
void asymoff_signing_parties_free(asymoff_signing_data_t **parties);

int asymoff_signing_online_execute_round_1(asymoff_signing_data_t *party);
int asymoff_signing_online_execute_round_2(asymoff_signing_data_t *party);
int asymoff_signing_online_execute_round_3(asymoff_signing_data_t *party);
int asymoff_signing_online_execute_final  (asymoff_signing_data_t *party);

uint64_t asymoff_signing_online_send_msg_1(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver);
uint64_t asymoff_signing_online_send_msg_2(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver);

int asymoff_signing_aggregate_execute_round_1(asymoff_signing_data_t *party);
int asymoff_signing_aggregate_execute_round_2(asymoff_signing_data_t *party);
int asymoff_signing_aggregate_execute_round_3(asymoff_signing_data_t *party);
int asymoff_signing_aggregate_execute_final  (asymoff_signing_data_t *party);

uint64_t asymoff_signing_aggregate_send_msg_1(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver);
uint64_t asymoff_signing_aggregate_send_msg_2(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver);
uint64_t asymoff_signing_aggregate_send_msg_3(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver);

void asymoff_signing_export_data(asymoff_party_data_t **parties, asymoff_signing_data_t ** const presign_parties);

int asymoff_signing_online_execute_mock_final (asymoff_signing_data_t **parties);

#endif