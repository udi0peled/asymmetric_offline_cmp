// Ephemeral Key
// ddh with dlog

#ifndef __ASYMOFF_ZKP_DOUBLE_EL_GAMAL_H__
#define __ASYMOFF_ZKP_DOUBLE_EL_GAMAL_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;

  ec_group_t ec;
  gr_elem_t g;
  gr_elem_t Y;
  gr_elem_t X;
  // end of partial

  gr_elem_t *B1;
  gr_elem_t *B2;
  gr_elem_t *V1;
  gr_elem_t *V2;

} zkp_double_el_gamal_public_t;

typedef struct
{
  scalar_t alpha;
  scalar_t beta;
  scalar_t gamma;
  // end of partial 

  scalar_t *b;
  scalar_t *v;
  scalar_t *k;

} zkp_double_el_gamal_secret_t;

typedef struct
{
  ec_group_t ec;

  gr_elem_t U1;
  gr_elem_t U2;
  gr_elem_t W1;
  gr_elem_t W2;
  
  // end of partial 

  scalar_t z;
  scalar_t w_1;
  scalar_t w_2;

} zkp_double_el_gamal_proof_t;

zkp_double_el_gamal_proof_t *
      zkp_double_el_gamal_new       (ec_group_t ec);
zkp_double_el_gamal_proof_t *
      zkp_double_el_gamal_duplicate (zkp_double_el_gamal_proof_t * const proof);
void  zkp_double_el_gamal_free      (zkp_double_el_gamal_proof_t *proof);

void  zkp_double_el_gamal_anchor  (zkp_double_el_gamal_proof_t *partial_proof, zkp_double_el_gamal_secret_t *partial_secret, const zkp_double_el_gamal_public_t *partial_public);
void  zkp_double_el_gamal_prove   (zkp_double_el_gamal_proof_t *proof, const zkp_double_el_gamal_secret_t *secret, const zkp_double_el_gamal_public_t *public, const zkp_aux_info_t *aux);
int   zkp_double_el_gamal_verify  (const zkp_double_el_gamal_proof_t *proof, const zkp_double_el_gamal_public_t *public, const zkp_aux_info_t *aux);

void zkp_double_el_gamal_aggregate_anchors      (zkp_double_el_gamal_proof_t *agg_anchor, zkp_double_el_gamal_proof_t ** const anchors, uint64_t num);
void zkp_double_el_gamal_aggregate_local_proofs (zkp_double_el_gamal_proof_t *agg_proof, zkp_double_el_gamal_proof_t ** const local_proofs, uint64_t num);

uint64_t zkp_double_el_gamal_proof_bytelen ();

#endif