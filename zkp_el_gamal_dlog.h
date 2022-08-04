// Ephemeral Key
// ddh with dlog

#ifndef __ASYMOFF_ZKP_EL_GAMAL_DLOG_H__
#define __ASYMOFF_ZKP_EL_GAMAL_DLOG_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;

  ec_group_t ec;
  gr_elem_t *R;
  gr_elem_t Y;

  // end of partial

  gr_elem_t *B1;
  gr_elem_t *B2;
  gr_elem_t *H;

} zkp_el_gamal_dlog_public_t;

typedef struct
{
  scalar_t *lambda;
  scalar_t *rho;
  
  // end of partial 

  scalar_t *b;
  scalar_t *k;
} zkp_el_gamal_dlog_secret_t;

typedef struct
{
  ec_group_t ec;

  gr_elem_t *V;
  gr_elem_t *W1;
  gr_elem_t *W2;

  hash_chunk anchor_hash;
  
  // end of partial 

  uint64_t batch_size;

  scalar_t *z;
  scalar_t *w;

} zkp_el_gamal_dlog_proof_t;

zkp_el_gamal_dlog_proof_t *
      zkp_el_gamal_dlog_new   (uint64_t batch_size, ec_group_t ec);
void  zkp_el_gamal_dlog_copy  (zkp_el_gamal_dlog_proof_t * copy_proof, zkp_el_gamal_dlog_proof_t * const proof);
void  zkp_el_gamal_dlog_free  (zkp_el_gamal_dlog_proof_t *proof);

void  zkp_el_gamal_dlog_anchor  (zkp_el_gamal_dlog_proof_t *partial_proof, zkp_el_gamal_dlog_secret_t *partial_secret, const zkp_el_gamal_dlog_public_t *partial_public);
void  zkp_el_gamal_dlog_prove   (zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_secret_t *secret, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash);
int   zkp_el_gamal_dlog_verify  (const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux, int use_hash);

void zkp_el_gamal_dlog_aggregate_anchors      (zkp_el_gamal_dlog_proof_t *agg_anchor, zkp_el_gamal_dlog_proof_t ** const anchors, uint64_t num);
void zkp_el_gamal_dlog_aggregate_local_proofs (zkp_el_gamal_dlog_proof_t *agg_proof, zkp_el_gamal_dlog_proof_t ** const local_proofs, uint64_t num);

uint64_t zkp_el_gamal_dlog_anchor_bytelen   (uint64_t batch_size, int use_hash);
uint64_t zkp_el_gamal_dlog_proof_bytelen    (uint64_t batch_size, int use_hash);

#endif