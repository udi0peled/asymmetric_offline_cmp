
#ifndef __ASYMOFF_SIGNING_CMP_H__
#define __ASYMOFF_SIGNING_CMP_H__

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
} asymoff_sign_cmp_msg_round_1_t;

typedef struct
{
} asymoff_sign_cmp_msg_round_2_t;

typedef struct
{
} asymoff_sign_cmp_msg_round_3_t;

typedef struct
{
} asymoff_sign_cmp_msg_round_4_t;

typedef struct 
{
  uint64_t i;
  uint64_t num_parties;

  zkp_aux_info_t *aux;

  ec_group_t ec;
  gr_elem_t gen;
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
    
  paillier_public_key_t **paillier_pub;
  ring_pedersen_public_t **rped_pub;
  
  asymoff_sign_cmp_msg_round_1_t *in_online_msg_1;
  asymoff_sign_cmp_msg_round_2_t *in_online_msg_2;
  asymoff_sign_cmp_msg_round_3_t *in_online_msg_3;
  asymoff_sign_cmp_msg_round_4_t *in_online_msg_4;

} asymoff_sign_cmp_data_t;

asymoff_sign_cmp_data_t **asymoff_signing_cmp_parties_new(asymoff_party_data_t ** parties, scalar_t *msgs, uint64_t sign_amount);
void asymoff_signing_cmp_parties_free(asymoff_sign_cmp_data_t **parties);

int asymoff_signing_cmp_execute_round_1(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_round_2(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_round_3(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_final  (asymoff_sign_cmp_data_t *party);

uint64_t asymoff_signing_cmp_send_msg_1(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);
uint64_t asymoff_signing_cmp_send_msg_2(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);
uint64_t asymoff_signing_cmp_send_msg_3(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);
uint64_t asymoff_signing_cmp_send_msg_4(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);

void asymoff_signing_cmp_export_data(asymoff_party_data_t **parties, asymoff_sign_cmp_data_t ** const presign_parties);

int asymoff_signing_cmp_execute_mock_export_data (asymoff_party_data_t **parties);

#endif