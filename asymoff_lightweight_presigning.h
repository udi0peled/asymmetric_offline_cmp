
#ifndef __ASYMOFF_LIGHTWEIGHT_PRESIGNING_H__
#define __ASYMOFF_LIGHTWEIGHT_PRESIGNING_H__

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "zkp_common.h"
#include "zkp_el_gamal.h"
#include "zkp_schnorr.h"
#include "asymoff_protocol.h"

typedef struct
{
  hash_chunk *T;

} asymoff_lightweight_presigning_aggregate_msg_round_1_t;

typedef struct
{
  gr_elem_t *B1;
  gr_elem_t *B2;

  zkp_el_gamal_proof_t *phi_ddh_anchor;

  hash_chunk *u;
  hash_chunk *echo_all_T;

} asymoff_lightweight_presigning_aggregate_msg_round_2_t;

typedef struct
{
  zkp_el_gamal_proof_t *phi_ddh_local_agg_proof;

} asymoff_lightweight_presigning_aggregate_msg_round_3_t;

typedef struct
{
  gr_elem_t *joint_B1;
  gr_elem_t *joint_B2;
  
  zkp_el_gamal_proof_t *phi_ddh_agg_proof;

  uint64_t aggregator_i;

} asymoff_lightweight_presigning_msg_to_offline_t;


typedef struct
{
  gr_elem_t *H;

  zkp_schnorr_proof_t *phi_sch;

} asymoff_lightweight_presigning_msg_from_offline_t;

typedef struct {

  scalar_t *alpha;
  gr_elem_t *H;

  zkp_schnorr_proof_t *phi_sch;

} asymoff_lightweight_presigning_data_offline_t;

typedef struct {

  gr_elem_t *B1;
  gr_elem_t *B2;

  gr_elem_t *joint_B1;
  gr_elem_t *joint_B2;
  
  scalar_t *b;
  scalar_t *k;

  hash_chunk T;
  hash_chunk u;
  hash_chunk echo_all_T;

  zkp_el_gamal_proof_t* phi_ddh_local_agg_proof;
  zkp_el_gamal_proof_t* phi_ddh_agg_proof;
  zkp_el_gamal_proof_t* phi_ddh_anchor;
  zkp_el_gamal_secret_t phi_ddh_anchor_secret;

} asymoff_lightweight_presigning_data_online_t;


typedef struct 
{
  uint64_t i;
  uint64_t num_parties;
  uint64_t batch_size;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t Y;

  paillier_public_key_t **paillier_pub;

  asymoff_lightweight_presigning_data_offline_t *offline;
  asymoff_lightweight_presigning_data_online_t  *online;
  
  asymoff_lightweight_presigning_aggregate_msg_round_1_t *in_msg_1;
  asymoff_lightweight_presigning_aggregate_msg_round_2_t *in_msg_2;
  asymoff_lightweight_presigning_aggregate_msg_round_3_t *in_msg_3;

  asymoff_lightweight_presigning_msg_to_offline_t        *msg_to_offline;
  asymoff_lightweight_presigning_msg_from_offline_t      *msg_from_offline;

} asymoff_lightweight_presigning_data_t;

asymoff_lightweight_presigning_data_t **
      asymoff_lightweight_presigning_parties_new(asymoff_party_data_t ** const parties, uint64_t batch_size);
void  asymoff_lightweight_presigning_parties_free(asymoff_lightweight_presigning_data_t **parties);

int asymoff_lightweight_presigning_aggregate_execute_round_1  (asymoff_lightweight_presigning_data_t *party);
int asymoff_lightweight_presigning_aggregate_execute_round_2  (asymoff_lightweight_presigning_data_t *party);
int asymoff_lightweight_presigning_aggregate_execute_round_3  (asymoff_lightweight_presigning_data_t *party);
int asymoff_lightweight_presigning_aggregate_execute_final    (asymoff_lightweight_presigning_data_t *party);
int asymoff_lightweight_presigning_execute_offline            (asymoff_lightweight_presigning_data_t *party);

uint64_t asymoff_lightweight_presigning_aggregate_send_msg_1  (asymoff_lightweight_presigning_data_t *sender, asymoff_lightweight_presigning_data_t *receiver);
uint64_t asymoff_lightweight_presigning_aggregate_send_msg_2  (asymoff_lightweight_presigning_data_t *sender, asymoff_lightweight_presigning_data_t *receiver);
uint64_t asymoff_lightweight_presigning_aggregate_send_msg_3  (asymoff_lightweight_presigning_data_t *sender, asymoff_lightweight_presigning_data_t *receiver);
uint64_t asymoff_lightweight_presigning_send_msg_to_offline   (asymoff_lightweight_presigning_data_t *sender, asymoff_lightweight_presigning_data_t *receiver);
uint64_t asymoff_lightweight_presigning_send_msg_from_offline (asymoff_lightweight_presigning_data_t *sender, asymoff_lightweight_presigning_data_t *receiver);

int asymoff_lightweight_presigning_export_data(asymoff_party_data_t **parties, asymoff_lightweight_presigning_data_t ** const presign_parties);

#endif