#ifndef __ASYMOFF_RANGE_ZKP_OPERATION_VS_GROUP_H__
#define __ASYMOFF_RANGE_ZKP_OPERATION_VS_GROUP_H__

#include "zkp_common.h"

typedef struct
{ 
  uint64_t x_range_bytes;
  uint64_t y_range_bytes;

  ring_pedersen_public_t *rped_pub;
  paillier_public_key_t *paillier_pub_0;    // Encrypted public C
  paillier_public_key_t *paillier_pub_1;    // Encrypted secret y
  ec_group_t G;
  gr_elem_t g;    

  scalar_t C;
  scalar_t Y;
  scalar_t D;
  gr_elem_t X;

} zkp_oper_group_commit_range_public_t;

typedef struct
{
  scalar_t x;       // x_range_bytes
  scalar_t y;       // y_range_bytes
  scalar_t rho;     // PAILLIER_MODULUS_BYTES
  scalar_t rho_y;   // PAILLIER_MODULUS_BYTES

} zkp_oper_group_commit_range_secret_t;

typedef struct
{
  
  scalar_t A;       // PAILLIER_MODULUS_BYTES * 2
  gr_elem_t B_x;    // GROUP_ELEMENT_BYTES
  scalar_t B_y;     // PAILLIER_MODULUS_BYTES * 2
  scalar_t E;       // RING_PED_MODULUS_BYTES
  scalar_t F;       // RING_PED_MODULUS_BYTES
  scalar_t S;       // RING_PED_MODULUS_BYTES
  scalar_t T;       // RING_PED_MODULUS_BYTES
  scalar_t z_1;     // x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  scalar_t z_2;     // y_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  scalar_t z_3;     // RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  scalar_t z_4;     // RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  scalar_t w;       // PAILLIER_MODULUS_BYTES
  scalar_t w_y;     // PAILLIER_MODULUS_BYTES

} zkp_oper_group_commit_range_proof_t;

zkp_oper_group_commit_range_proof_t *
     zkp_oper_group_commit_range_new              (const ec_group_t G);
void zkp_oper_group_commit_range_free             (zkp_oper_group_commit_range_proof_t *proof);
void zkp_oper_group_commit_range_prove            (zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_secret_t *secret, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux);
int  zkp_oper_group_commit_range_verify           (const zkp_oper_group_commit_range_proof_t *proof, const zkp_oper_group_commit_range_public_t *public, const zkp_aux_info_t *aux);

uint64_t zkp_oper_group_commit_range_bytelen(uint64_t x_range_bytes, uint64_t y_range_bytes);

#endif