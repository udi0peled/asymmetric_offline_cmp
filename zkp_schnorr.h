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
 *  When using <...>_commit, the group and generator ec,g values needs to be already populated (externally).
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated.
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 *  
 */

#ifndef __ASYMOFF_ZKP_SCHNORR_H__
#define __ASYMOFF_ZKP_SCHNORR_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;
  ec_group_t ec;

  // end of partial

  gr_elem_t *X;    // GROUP_ELEMENT_BYTES x batch_size
} zkp_schnorr_public_t;

typedef struct
{
  scalar_t a;

  // end of partial

  scalar_t *x;     // GROUP_ORDER_BYTES x batch_size
} zkp_schnorr_secret_t;

typedef struct
{
  gr_elem_t A;    // GROUP_ELEMENT_BYTES
  
  // end of partial

  scalar_t z;     // GROUP_ORDER_BYTES
} zkp_schnorr_proof_t;

zkp_schnorr_proof_t *
      zkp_schnorr_new              (const ec_group_t ec);
void  zkp_schnorr_free             (zkp_schnorr_proof_t *proof);
void  zkp_schnorr_anchor           (zkp_schnorr_proof_t *partial_proof, zkp_schnorr_secret_t *partial_secret, const zkp_schnorr_public_t *partial_public);
void  zkp_schnorr_copy_anchor      (zkp_schnorr_proof_t *copy_anchor, const zkp_schnorr_proof_t *anchor);
void  zkp_schnorr_prove            (zkp_schnorr_proof_t *proof, const zkp_schnorr_secret_t *secret, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux);
int   zkp_schnorr_verify           (const zkp_schnorr_proof_t *proof, const zkp_schnorr_public_t *public, const zkp_aux_info_t *aux);
uint64_t zkp_schnorr_proof_bytelen();

#endif