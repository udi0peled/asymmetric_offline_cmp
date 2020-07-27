/**
 * 
 *  Name:
 *  zkp_group_vs_paillier_range
 *  
 *  Description:
 *  Group Element vs Paillier Paillier Encryption in Range Zero Knowledge Proof
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_GROUP_VS_PAILLIER_H__
#define __CMP20_ECDSA_MPC_ZKP_GROUP_VS_PAILLIER_H__

#include "zkp_common.h"

typedef struct
{
  struct { 
    uint64_t x_range_bytes;
    ring_pedersen_public_t *rped_pub;
    paillier_public_key_t *paillier_pub;
    ec_group_t G;
    gr_elem_t g;    // GROUP_ELEMENT_BYTES
    scalar_t C;     // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t X;    // GROUP_ELEMENT_BYTES
  } public;

  struct {
    scalar_t x;     // x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t rho;   // PAILLIER_MODULUS_BYTES
  } secret;

  struct {
    scalar_t S;     // RING_PED_MODULUS_BYTES
    scalar_t A;     // PAILLIER_MODULUS_BYTES * 2
    gr_elem_t Y;    // GROUP_ELEMENT_BYTES
    scalar_t D;     // RING_PED_MODULUS_BYTES
    scalar_t z_1;   // x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
    scalar_t z_2;   // PAILLIER_MODULUS_BYTES
    scalar_t z_3;   // RING_PED_MODULUS_BYTES + x_range_bytes + EPS_ZKP_SLACK_PARAMETER_BYTES
  } proof;
} zkp_group_vs_paillier_range_t;

zkp_group_vs_paillier_range_t *
     zkp_group_vs_paillier_range_new            ();
void zkp_group_vs_paillier_range_free           (zkp_group_vs_paillier_range_t *zkp);
void zkp_group_vs_paillier_range_prove          (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux);
int  zkp_group_vs_paillier_range_verify         (zkp_group_vs_paillier_range_t *zkp, const zkp_aux_info_t *aux);
void zkp_group_vs_paillier_range_proof_to_bytes (uint8_t **bytes, uint64_t *byte_len, const zkp_group_vs_paillier_range_t *zkp, uint64_t x_range_bytes, int move_to_end);

#endif