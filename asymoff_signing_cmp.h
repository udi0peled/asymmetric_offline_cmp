
#ifndef __ASYMOFF_SIGNING_CMP_H__
#define __ASYMOFF_SIGNING_CMP_H__

#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "zkp_common.h"
#include "zkp_el_gamal_dlog.h"
#include "zkp_range_el_gamal_commitment.h"
#include "zkp_operation_group_commitment_range.h"
#include "asymoff_protocol.h"

typedef struct
{
  scalar_t *K;
  scalar_t *G;
  
  gr_elem_t *Gamma1;
  gr_elem_t *Gamma2;

  zkp_range_el_gamal_proof_t  *theta_Rddh_G;
  zkp_range_el_gamal_proof_t  *theta_Rddh_K;

} asymoff_sign_cmp_msg_round_1_t;

typedef struct
{

  scalar_t *D;
  scalar_t *F;
  scalar_t *D_hat;
  scalar_t *F_hat;
  
  gr_elem_t *H_gamma;

  zkp_el_gamal_dlog_proof_t           *phi_ddh_H_gamma;
  zkp_oper_group_commit_range_proof_t **phi_affg_X;
  zkp_oper_group_commit_range_proof_t **phi_affg_H;
  
} asymoff_sign_cmp_msg_round_2_t;

typedef struct
{
  scalar_t  *delta;
  gr_elem_t *Delta;

  zkp_el_gamal_dlog_proof_t   *psi_ddh_Delta;

} asymoff_sign_cmp_msg_round_3_t;

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
  
  gr_elem_t **B1;
  gr_elem_t **B2;
  gr_elem_t *H;
  scalar_t  *b;
  scalar_t  *nonce;
  gr_elem_t *R;
  scalar_t *chi;

  scalar_t *G;
  scalar_t *K;
  scalar_t *rho;
  scalar_t *nu;
  scalar_t *z;
  scalar_t *delta;
  scalar_t *gamma;

  gr_elem_t *H_gamma;
  gr_elem_t *Delta;
  gr_elem_t *Gamma1;
  gr_elem_t *Gamma2;
  gr_elem_t *Lambda;

  scalar_t **beta;
  scalar_t **beta_hat;

  scalar_t **D;
  scalar_t **F;
  scalar_t **D_hat;
  scalar_t **F_hat;

  //zkp_encryption_in_range_proof_t        **psi_enc;
  // zkp_oper_paillier_commit_range_proof_t **psi_affp;

  zkp_el_gamal_dlog_proof_t   *phi_ddh_H_Gamma;
  zkp_el_gamal_dlog_proof_t   *psi_ddh_Delta;

  zkp_range_el_gamal_proof_t  **theta_Rddh_G;
  zkp_range_el_gamal_proof_t  **theta_Rddh_K;
  
  zkp_oper_group_commit_range_proof_t ***phi_affg_X;
  zkp_oper_group_commit_range_proof_t ***phi_affg_H;
  
  paillier_private_key_t *paillier_priv;
  paillier_public_key_t **paillier_pub;
  ring_pedersen_public_t **rped_pub;
  
  asymoff_sign_cmp_msg_round_1_t *in_cmp_msg_1;
  asymoff_sign_cmp_msg_round_2_t *in_cmp_msg_2;
  asymoff_sign_cmp_msg_round_3_t *in_cmp_msg_3;

} asymoff_sign_cmp_data_t;

asymoff_sign_cmp_data_t **asymoff_signing_cmp_parties_new(asymoff_party_data_t ** parties, uint64_t num_sigs);
void asymoff_signing_cmp_parties_free(asymoff_sign_cmp_data_t **parties);

int asymoff_signing_cmp_execute_round_1(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_round_2(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_round_3(asymoff_sign_cmp_data_t *party);
int asymoff_signing_cmp_execute_final  (asymoff_sign_cmp_data_t *party);

uint64_t asymoff_signing_cmp_send_msg_1(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);
uint64_t asymoff_signing_cmp_send_msg_2(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);
uint64_t asymoff_signing_cmp_send_msg_3(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver);

void asymoff_signing_cmp_export_data(asymoff_party_data_t **parties, asymoff_sign_cmp_data_t ** const cmp_parties);

int asymoff_signing_cmp_execute_mock_export_data (asymoff_party_data_t **parties);

#endif