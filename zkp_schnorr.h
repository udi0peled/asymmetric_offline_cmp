/**
 * 
 *  Name:
 *  zkp_schnorr
 *  
 *  Description:
 *  Schnorr Zero Knowledge Proof
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_commit, the group and generator G,g values needs to be already populated (externally).
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated.
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 *  
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_SCHNORR_H__
#define __CMP20_ECDSA_MPC_ZKP_SCHNORR_H__

#include "zkp_common.h"

typedef struct
{
  ec_group_t G;
  gr_elem_t g;    // GROUP_ELEMENT_BYTES
  gr_elem_t X;    // GROUP_ELEMENT_BYTES

} zkp_schnorr_public_t;

typedef struct
{
  scalar_t x;     // GROUP_ORDER_BYTES

} zkp_schnorr_secret_t;

typedef struct
{
  gr_elem_t A;    // GROUP_ELEMENT_BYTES
  scalar_t z;     // GROUP_ORDER_BYTES

} zkp_schnorr_proof_t;

zkp_schnorr_proof_t *
      zkp_schnorr_new              (const ec_group_t G);
void  zkp_schnorr_free             (zkp_schnorr_proof_t *proof);
// Sets A field of proof, and returns secret alpha which generated A (to be used when proving later). G,g fields must already be populated when calling.
void  zkp_schnorr_commit           (gr_elem_t commited_A, scalar_t alpha, const zkp_schnorr_public_t *public);
// Using secret alpha (generated by commiting before). alpha==NULL is sampled random. 
void  zkp_schnorr_prove            (zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const scalar_t alpha, const zkp_schnorr_secret_t *secret, const zkp_aux_info_t *aux);
int   zkp_schnorr_verify           (const zkp_schnorr_public_t *public, const zkp_schnorr_proof_t *proof, const zkp_aux_info_t *aux);
void  zkp_schnorr_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_schnorr_proof_t *proof, const ec_group_t G, int move_to_end);
void  zkp_schnorr_proof_from_bytes (zkp_schnorr_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, const ec_group_t G, int move_to_end);
#endif