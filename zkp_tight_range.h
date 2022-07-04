/**
 * 
 *  Name:
 *  zkp_tight_range
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

#ifndef __CMP20_ECDSA_MPC_ZKP_TIGHT_RANGE_H__
#define __CMP20_ECDSA_MPC_ZKP_TIGHT_RANGE_H__

#include "zkp_common.h"

typedef struct
{ 
  ring_pedersen_public_t *rped_pub;
  paillier_public_key_t *paillier_pub;
  ec_group_t G;
  gr_elem_t g;    
  gr_elem_t X;       
  scalar_t W;
} zkp_tight_range_public_t;

typedef struct
{
  scalar_t alpha_1;
  scalar_t alpha_2;
  scalar_t alpha_3;

} zkp_tight_range_positive_splitting_t;

typedef struct
{
  scalar_t x;
  scalar_t rho;

  zkp_tight_range_positive_splitting_t *splitting;

} zkp_tight_range_secret_t;

typedef struct
{
  scalar_t S;
  scalar_t T_1;   
  scalar_t T_2;   
  scalar_t T_3;  

  hash_chunk anchor_hash;

  scalar_t z_1; 
  scalar_t z_2;
  scalar_t z_3;
  scalar_t w_1;
  scalar_t w_2;
  scalar_t w_3;
  scalar_t sigma;
  scalar_t tau;
  scalar_t delta;
  scalar_t eta;

} zkp_tight_range_proof_t;

zkp_tight_range_proof_t *
          zkp_tight_range_new           ();
void      zkp_tight_range_free          (zkp_tight_range_proof_t *proof);
void      zkp_tight_range_prove         (zkp_tight_range_proof_t *proof, const zkp_tight_range_secret_t *secret, const zkp_tight_range_public_t *public, const zkp_aux_info_t *aux);
int       zkp_tight_range_verify        (const zkp_tight_range_proof_t *proof, const zkp_tight_range_public_t *public, const zkp_aux_info_t *aux);
uint64_t  zkp_tight_range_proof_bytelen ();

zkp_tight_range_positive_splitting_t *
     zkp_tight_range_splitting_new      (scalar_t secret);
void zkp_tight_range_splitting_free     (zkp_tight_range_positive_splitting_t *splitting);



//void zkp_tight_range_proof_to_bytes   (uint8_t **bytes, uint64_t *byte_len, const zkp_tight_range_proof_t *proof, uint64_t x_range_bytes, const ec_group_t G, int move_to_end);
//void zkp_tight_range_proof_from_bytes (zkp_tight_range_proof_t *proof, uint8_t **bytes, uint64_t *byte_len, uint64_t x_range_bytes, const scalar_t N0, const ec_group_t G, int move_to_end);

#endif