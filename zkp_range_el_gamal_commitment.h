#ifndef __ASYMOFF_ZKP_RANGE_EL_GAMAL_H__
#define __ASYMOFF_ZKP_RANGE_EL_GAMAL_H__

#include "zkp_common.h"

typedef struct
{ 
  ring_pedersen_public_t *rped_pub;
  paillier_public_key_t *paillier_pub;
  ec_group_t ec;
  gr_elem_t g;

  gr_elem_t Y;

  uint64_t batch_size;
  scalar_t  *packed_C;
  gr_elem_t *A1;
  gr_elem_t *A2;

} zkp_range_el_gamal_public_t;

typedef struct
{
  scalar_t *x;
  scalar_t *rho;
  scalar_t *b;

} zkp_range_el_gamal_secret_t;

typedef struct
{
  uint64_t batch_size;
  
  scalar_t *packed_S;
  scalar_t packed_D;
  gr_elem_t V1[PACKING_SIZE];
  gr_elem_t V2[PACKING_SIZE];
  scalar_t packed_T;   

  scalar_t z_1[PACKING_SIZE]; 
  scalar_t packed_z_2;
  scalar_t packed_z_3;
  scalar_t w[PACKING_SIZE];

} zkp_range_el_gamal_proof_t;

zkp_range_el_gamal_proof_t *
          zkp_range_el_gamal_new           (uint64_t batch_size, ec_group_t ec);
void      zkp_range_el_gamal_free          (zkp_range_el_gamal_proof_t *proof);
void      zkp_range_el_gamal_prove         (zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_secret_t *secret, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux);
int       zkp_range_el_gamal_verify        (const zkp_range_el_gamal_proof_t *proof, const zkp_range_el_gamal_public_t *public, const zkp_aux_info_t *aux);
uint64_t  zkp_range_el_gamal_proof_bytelen (uint64_t batch_size);


#endif