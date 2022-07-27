#ifndef __ASYMOFF_PROTOCOL_H_
#define __ASYMOFF_PROTOCOL_H_

#include "common.h"
#include "zkp_common.h"
#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"

typedef struct 
{
  uint64_t i;
  uint64_t num_parties;

  hash_chunk sid;
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

  uint64_t batch_size;
  uint64_t num_sigs;
  uint64_t curr_index;
  uint64_t next_index;

  gr_elem_t *H;
  scalar_t *nonce;
  scalar_t *b;
  scalar_t *chi;
  gr_elem_t *R;

  gr_elem_t  **B1;
  gr_elem_t  **B2;
  gr_elem_t *joint_B1;
  gr_elem_t *joint_B2;
  gr_elem_t *joint_V1;
  gr_elem_t *joint_V2;
  
} asymoff_party_data_t;


asymoff_party_data_t **
     asymoff_protocol_parties_new(uint64_t num_parties);
void asymoff_protocol_parties_free(asymoff_party_data_t **parties);
void asymoff_protocol_parties_set(asymoff_party_data_t **parties, hash_chunk sid, scalar_t *private_x);

void asymoff_protocol_parties_new_batch(asymoff_party_data_t **parties, uint64_t batch_size);
void asymoff_protocol_parties_free_batch(asymoff_party_data_t **parties);

#endif