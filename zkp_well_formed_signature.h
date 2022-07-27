#ifndef __ASYMOFF_ZKP_WELL_FORMED_SIGNATURE_H__
#define __ASYMOFF_ZKP_WELL_FORMED_SIGNATURE_H__

#include "zkp_common.h"

typedef struct
{
  uint64_t batch_size;

  ec_group_t ec;
  gr_elem_t g;
  gr_elem_t Y;
  scalar_t  W;

  paillier_public_key_t *paillier_pub;
  ring_pedersen_public_t *rped_pub;
  // end of partial

  scalar_t *packed_Z;
  scalar_t *packed_S;
  gr_elem_t *L1;
  gr_elem_t *L2;
  gr_elem_t *U1;
  gr_elem_t *U2;

} zkp_well_formed_signature_public_t;

typedef struct
{
  
  scalar_t alpha   [PACKING_SIZE];
  scalar_t beta    [PACKING_SIZE];
  scalar_t delta_LB[PACKING_SIZE];
  scalar_t delta_UA[PACKING_SIZE];
  scalar_t r;
  scalar_t nu;

  // end of partial 

  scalar_t *xi;
  scalar_t *mu;
  scalar_t *rho;
  scalar_t *lambda;
  scalar_t *gamma_LB;  
  scalar_t *gamma_UA;  

} zkp_well_formed_signature_secret_t;

typedef struct
{
  ec_group_t ec;

  scalar_t V;
  scalar_t T;

  gr_elem_t A1[PACKING_SIZE];
  gr_elem_t A2[PACKING_SIZE];
  gr_elem_t B1[PACKING_SIZE];
  gr_elem_t B2[PACKING_SIZE];
  
  // end of partial 

  scalar_t z_UA    [PACKING_SIZE];
  scalar_t z_LB    [PACKING_SIZE];
  scalar_t sigma_UA[PACKING_SIZE];
  scalar_t sigma_LB[PACKING_SIZE];
  scalar_t d;
  scalar_t w;


} zkp_well_formed_signature_proof_t;

zkp_well_formed_signature_proof_t *
      zkp_well_formed_signature_new   (ec_group_t ec);
void  zkp_well_formed_signature_copy  (zkp_well_formed_signature_proof_t * copy_proof, zkp_well_formed_signature_proof_t * const proof);
void  zkp_well_formed_signature_free  (zkp_well_formed_signature_proof_t *proof);

void  zkp_well_formed_signature_anchor  (zkp_well_formed_signature_proof_t *partial_proof, zkp_well_formed_signature_secret_t *partial_secret, const zkp_well_formed_signature_public_t *partial_public);
void  zkp_well_formed_signature_prove   (zkp_well_formed_signature_proof_t *proof, const zkp_well_formed_signature_secret_t *secret, const zkp_well_formed_signature_public_t *public, const zkp_aux_info_t *aux);
int   zkp_well_formed_signature_verify  (const zkp_well_formed_signature_proof_t *proof, const zkp_well_formed_signature_public_t *public, const zkp_aux_info_t *aux, int agg_range_slack);

void zkp_well_formed_signature_aggregate_anchors      (zkp_well_formed_signature_proof_t *agg_anchor, zkp_well_formed_signature_proof_t ** const anchors, uint64_t num, const paillier_public_key_t *paillier_pub, const ring_pedersen_public_t *rped_pub);
void zkp_well_formed_signature_aggregate_local_proofs (zkp_well_formed_signature_proof_t *agg_proof, zkp_well_formed_signature_proof_t ** const local_proofs, uint64_t num, const paillier_public_key_t *paillier_pub);

uint64_t zkp_well_formed_signature_proof_bytelen ();

#endif