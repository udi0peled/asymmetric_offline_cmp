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

#ifndef __ASYMOFF_ZKP_RANGE_EL_GAMAL_H__
#define __ASYMOFF_ZKP_RANGE_EL_GAMAL_H__

#include "zkp_common.h"

typedef struct
{ 
  ring_pedersen_public_t *rped_pub;
  paillier_public_key_t *paillier_pub;
  ec_group_t G;
  gr_elem_t g;

  gr_elem_t Y;

  uint64_t batch_size;
  scalar_t  *C;
  gr_el_pack_t *A1;
  gr_el_pack_t *A2;

} zkp_range_el_gamal_public_t;

typedef struct
{
  scalar_pack_t *x;
  scalar_t *rho;
  scalar_pack_t *b;

} zkp_range_el_gamal_secret_t;

typedef struct
{
  uint64_t batch_size;
  
  scalar_t *S;
  scalar_t D;
  gr_el_pack_t V1;
  gr_el_pack_t V2;
  scalar_t T;   

  scalar_pack_t z_1; 
  scalar_t z_2;
  scalar_t z_3;
  scalar_pack_t w;

} zkp_range_el_gamal_proof_t;

zkp_range_el_gamal_proof_t *
          zkp_range_el_gamal_new           (uint64_t batch_size, ec_group_t ec);
void      zkp_range_el_gamal_free          (zkp_range_el_gamal_proof_t *proof);
void      zkp_range_el_gamal_prove         (zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_secret_t *secret, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux);
int       zkp_range_el_gamal_verify        (const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux);
uint64_t  zkp_range_el_gamal_proof_bytelen (uint64_t batch_size);


#endif