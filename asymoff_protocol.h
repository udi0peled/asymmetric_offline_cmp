#ifndef __ASYMOFF_PROTOCOL__
#define __ASYMOFF_PROTOCOL__

#include "common.h"
#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"
#include "asymoff_key_generation.h"


typedef struct 
{
  uint64_t i;
  uint64_t num_parties;

  hash_chunk srid;

  ec_group_t ec;
  gr_elem_t gen;

  scalar_t  x;
  gr_elem_t *X;
  gr_elem_t Y;

  paillier_private_key_t *paillier_priv;
  paillier_public_key_t **paillier_pub;

  ring_pedersen_private_t *rped_priv;
  ring_pedersen_public_t **rped_pub;
  
  scalar_t W_0;

} asymoff_party_data_t;


asymoff_party_data_t **asymoff_protocol_parties_new(uint64_t num_parties);
void asymoff_protocol_parties_free(asymoff_party_data_t **parties);

void asymoff_save_data_from_key_gen(asymoff_party_data_t **parties, asymoff_key_gen_data_t **kgd_parties);

#endif