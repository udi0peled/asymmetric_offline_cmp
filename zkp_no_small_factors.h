/**
 * 
 *  Name:
 *  zkp_paillier_blum_modulus
 *  
 *  Description:
 *  Paillier Blum Modulus Zero Knowledge Proof for modulus of PAILLIER_MODULUS_BYTES byte length (hardcoded in verification).
 * 
 *  Usage:
 *  Constructor and destructor for zkp_<...>_t don't set any values and handles only proof fields.
 *  When using <...>_prove, all public and secret fields of zkp_<...>_t needs to be already populated (externally).
 *  Calling <...>_prove sets only the proof fields.
 *  When using <...>_verify, all public and proof fields of zkp_<...>_t need to be already populated.
 *  Calling <...>_verify return 0/1 (fail/pass).
 * 
 */

#ifndef __CMP20_ECDSA_MPC_ZKP_NO_SMALL_FACTORS_H__
#define __CMP20_ECDSA_MPC_ZKP_NO_SMALL_FACTORS_H__

#include "zkp_common.h"
#include "ring_pedersen_parameters.h"


typedef struct
{
  scalar_t P;
  scalar_t Q;
  scalar_t A;
  scalar_t B;
  scalar_t T;
  
  scalar_t z_1;
  scalar_t z_2;
  scalar_t w_1;
  scalar_t w_2;
  scalar_t v;

} zkp_no_small_factors_t;

zkp_no_small_factors_t *
     zkp_no_small_factors_new              ();
void zkp_no_small_factors_free             (zkp_no_small_factors_t *proof);
void zkp_no_small_factors_prove            (zkp_no_small_factors_t *proof, const paillier_private_key_t *paillier_priv, const ring_pedersen_public_t *rped_pub, const zkp_aux_info_t *aux);
int  zkp_no_small_factors_verify           (zkp_no_small_factors_t *proof, const paillier_public_key_t *paillier_pub, const ring_pedersen_public_t *rped_pub, const zkp_aux_info_t *aux);
uint64_t zkp_no_small_factors_proof_bytelen();

//void zkp_no_small_factors_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_no_small_factors_t *proof, int move_to_end);
//void zkp_no_small_factors_proof_from_bytes (zkp_no_small_factors_t *proof, uint8_t **bytes, uint64_t *byte_len, int move_to_end);

#endif