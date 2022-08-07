#ifndef __ASYMOFF_ZKP_EL_GAMAL_H__
#define __ASYMOFF_ZKP_EL_GAMAL_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;

  ec_group_t ec;
  gr_elem_t Y;

  // end of partial

  gr_elem_t *B1;
  gr_elem_t *B2;

} zkp_el_gamal_public_t;

typedef struct
{
  scalar_t lambda;
  scalar_t alpha;
  
  // end of partial 

  scalar_t *b;
  scalar_t *k;
} zkp_el_gamal_secret_t;

typedef struct
{
  ec_group_t ec;

  gr_elem_t A1;
  gr_elem_t A2;

  // end of partial 

  scalar_t z;
  scalar_t w;

} zkp_el_gamal_proof_t;

zkp_el_gamal_proof_t *
      zkp_el_gamal_new   (ec_group_t ec);
void  zkp_el_gamal_copy_anchor  (zkp_el_gamal_proof_t * copy_anchor, zkp_el_gamal_proof_t * const anchor);
void  zkp_el_gamal_free  (zkp_el_gamal_proof_t *proof);

void  zkp_el_gamal_anchor  (zkp_el_gamal_proof_t *partial_proof, zkp_el_gamal_secret_t *partial_secret, const zkp_el_gamal_public_t *partial_public);
void  zkp_el_gamal_prove   (zkp_el_gamal_proof_t *proof, const zkp_el_gamal_secret_t *secret, const zkp_el_gamal_public_t *public, const zkp_aux_info_t *aux);
int   zkp_el_gamal_verify  (const zkp_el_gamal_proof_t *proof, const zkp_el_gamal_public_t *public, const zkp_aux_info_t *aux);

void zkp_el_gamal_aggregate_anchors      (zkp_el_gamal_proof_t *agg_anchor, zkp_el_gamal_proof_t ** const anchors, uint64_t num);
void zkp_el_gamal_aggregate_local_proofs (zkp_el_gamal_proof_t *agg_proof, zkp_el_gamal_proof_t ** const local_proofs, uint64_t num);

uint64_t zkp_el_gamal_anchor_bytelen   ();
uint64_t zkp_el_gamal_proof_bytelen    ();

#endif