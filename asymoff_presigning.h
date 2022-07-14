
#ifndef __ASYMOFF_PRESIGNING_H__
#define __ASYMOFF_PRESIGNING_H__


#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "zkp_common.h"
#include "zkp_range_el_gamal_commitment.h"
#include "zkp_el_gamal_dlog.h"
#include "asymoff_protocol.h"

typedef struct
{
  // TODO: Commit/Reveal for B1/2?

  gr_el_pack_t *B1;
  gr_el_pack_t *B2;
  scalar_t  *Paillier_K;

  zkp_range_el_gamal_proof_t *phi_Rddh;

} asymoff_presigning_msg_round_1_t;

typedef struct
{
  scalar_t *C;
  gr_el_pack_t *A1;
  gr_el_pack_t *A2;
  gr_el_pack_t *H;

  zkp_el_gamal_dlog_proof_t *phi_eph;
  zkp_range_el_gamal_proof_t *phi_Rddh;

} asymoff_presigning_msg_round_2_t;

typedef struct {

  scalar_pack_t *alpha;
  gr_el_pack_t *H;
  gr_el_pack_t *A1;
  gr_el_pack_t *A2;

  scalar_t *Paillier_C;

  zkp_el_gamal_dlog_proof_t *phi_eph;
  zkp_range_el_gamal_proof_t **phi_Rddh;

} asymoff_presigning_data_offline_t;

typedef struct {

  gr_el_pack_t *B1;
  gr_el_pack_t *B2;

  scalar_t *Paillier_K;

  zkp_range_el_gamal_proof_t **phi_Rddh;

} asymoff_presigning_data_online_t;


typedef struct 
{
  hash_chunk sid;
  uint64_t i;
  uint64_t num_parties;
  uint64_t batch_size;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t gen;
  gr_elem_t Y;

  paillier_public_key_t **paillier_pub;
  ring_pedersen_public_t **rped_pub;

  asymoff_presigning_data_offline_t *offline;
  asymoff_presigning_data_online_t  *online;
  
  // Array of in coming messages from other parties
  asymoff_presigning_msg_round_1_t *in_msg_1;
  asymoff_presigning_msg_round_2_t *in_msg_2;

} asymoff_presigning_data_t;

asymoff_presigning_data_t **asymoff_presigning_parties_new(asymoff_party_data_t **parties, uint64_t packed_batch_size);
void asymoff_presigning_parties_free(asymoff_presigning_data_t **parties);

int asymoff_presigning_compute_round_1(asymoff_presigning_data_t *party);
int asymoff_presigning_compute_round_2(asymoff_presigning_data_t *party);
int asymoff_presigning_compute_final  (asymoff_presigning_data_t *party);

uint64_t asymoff_presigning_send_msg_1(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver);
uint64_t asymoff_presigning_send_msg_2(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver);

void asymoff_presigning_export_data(asymoff_party_data_t **parties, asymoff_presigning_data_t **presign_parties);

#endif