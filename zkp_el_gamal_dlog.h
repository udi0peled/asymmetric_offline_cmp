// Ephemeral Key
// ddh with dlog

#ifndef __ASYMOFF_ZKP_EL_GAMAL_DLOG_H__
#define __ASYMOFF_ZKP_EL_GAMAL_DLOG_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;

  ec_group_t G;
  gr_elem_t g;
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
  hash_chunk anchor_hash;
  // end of partial 

  uint64_t batch_size;

  scalar_t *z;
  scalar_t *w;

} zkp_el_gamal_dlog_proof_t;

zkp_el_gamal_dlog_proof_t *
      zkp_el_gamal_dlog_new              (uint64_t batch_size);
void  zkp_el_gamal_dlog_free             (zkp_el_gamal_dlog_proof_t *proof);
void  zkp_el_gamal_dlog_anchor           (zkp_el_gamal_dlog_proof_t *partial_proof, zkp_el_gamal_dlog_secret_t *partial_secret, const zkp_el_gamal_dlog_public_t *partial_public);
void  zkp_el_gamal_dlog_prove            (zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_secret_t *secret, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux);
int   zkp_el_gamal_dlog_verify           (const zkp_el_gamal_dlog_proof_t *proof, const zkp_el_gamal_dlog_public_t *public, const zkp_aux_info_t *aux);
uint64_t zkp_el_gamal_dlog_proof_bytelen();

#endif