#include "asymoff_protocol.h"
#include <openssl/rand.h>

asymoff_party_data_t **asymoff_protocol_parties_new(uint64_t num_parties) {

  asymoff_party_data_t **parties = calloc(num_parties, sizeof(asymoff_party_data_t*));

  for (uint64_t i = 0; i < num_parties; ++i) {
    parties[i] = malloc(sizeof(asymoff_party_data_t));

    parties[i]->i = i;
    parties[i]->num_parties = num_parties;

    ec_group_t ec = ec_group_new();
    parties[i]->ec = ec;
    parties[i]->gen = ec_group_generator(ec);

    parties[i]->x = scalar_new();
    parties[i]->X = calloc(num_parties, sizeof(gr_elem_t));
    parties[i]->Y = group_elem_new(ec);

    parties[i]->paillier_priv = paillier_encryption_private_new();
    parties[i]->paillier_pub = calloc(num_parties, sizeof(paillier_public_key_t));
  
    parties[i]->rped_priv = ring_pedersen_private_new();
    parties[i]->rped_pub = calloc(num_parties, sizeof(ring_pedersen_public_t));
  
    for (uint64_t j = 0; j < num_parties; ++j) {
        parties[i]->X[j] = group_elem_new(ec);
        parties[i]->paillier_pub[j] = paillier_encryption_public_new();
        parties[i]->rped_pub[j] = ring_pedersen_public_new();
    }
    
    if (i != 0) parties[i]->W_0 = scalar_new();
  }
  
  return parties;
}

void asymoff_protocol_parties_free(asymoff_party_data_t **parties) {

  uint64_t num_parties = parties[0]->num_parties;

  for (uint64_t i = 0; i < num_parties; ++i) {

    for (uint64_t j = 0; j < num_parties; ++j) {
        group_elem_free(parties[i]->X[j]);
        paillier_encryption_free_keys(NULL, parties[i]->paillier_pub[j]);
        ring_pedersen_free_param(NULL, parties[i]->rped_pub[j]);
    }
    free(parties[i]->X);
    free(parties[i]->paillier_pub);
    free(parties[i]->rped_pub);

    scalar_free(parties[i]->x);
    group_elem_free(parties[i]->Y);
    paillier_encryption_free_keys(parties[i]->paillier_priv, NULL);
    ring_pedersen_free_param(parties[i]->rped_priv, NULL);
    ec_group_free(parties[i]->ec);

    if (i != 0) scalar_free(parties[i]->W_0);

    free(parties[i]);
  }

  free(parties);
}

void asymoff_protocol_parties_set(asymoff_party_data_t **parties, hash_chunk sid, scalar_t *private_x)
{
  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec = parties[0]->ec;
  hash_chunk sid_init;

  if (sid) {
    memcpy(sid_init, sid, sizeof(hash_chunk));
  } else {
    RAND_bytes(sid_init, sizeof(hash_chunk));
  }

  for(uint64_t i = 0; i < num_parties; ++i) {

    memcpy(parties[i]->sid, sid_init, sizeof(hash_chunk));

    if (private_x) {
      scalar_copy(parties[i]->x, private_x[i]);
    } else {
      scalar_sample_in_range(parties[i]->x, ec_group_order(ec) , 0);
    }
  }
}

void asymoff_protocol_parties_new_batch(asymoff_party_data_t **parties, uint64_t batch_size) {

  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec = parties[0]->ec;

  for (uint64_t i = 0; i < num_parties; ++i) {
    
    parties[i]->batch_size = batch_size;
    
    parties[i]->H     = new_gr_el_array(batch_size, ec);
    parties[i]->b     = new_scalar_array(batch_size);
    parties[i]->nonce = new_scalar_array(batch_size);
    
    uint64_t B_num = (i == 0 ? 1 : num_parties);

    parties[i]->B_num = B_num;
    parties[i]->B1 = calloc(parties[i]->B_num, sizeof(gr_elem_t*));
    parties[i]->B2 = calloc(parties[i]->B_num, sizeof(gr_elem_t*));

    for (uint64_t l = 0; l < B_num; ++l) {
      parties[i]->B1[l] = new_gr_el_array(batch_size, ec);
      parties[i]->B2[l] = new_gr_el_array(batch_size, ec);
    }
  }
}

void asymoff_protocol_parties_free_batch(asymoff_party_data_t **parties) {
  
  uint64_t num_parties = parties[0]->num_parties;
  uint64_t batch_size = parties[0]->batch_size;

  for (uint64_t i = 0; i < num_parties; ++i) {
    
    free_gr_el_array(parties[i]->H, batch_size);
    free_scalar_array(parties[i]->b, batch_size);
    free_scalar_array(parties[i]->nonce, batch_size);
    
    for (uint64_t l = 0; l < parties[i]->B_num; ++l) {
      free_gr_el_array(parties[i]->B1[l], batch_size);
      free_gr_el_array(parties[i]->B2[l], batch_size);
    }

    free(parties[i]->B1);
    free(parties[i]->B2);
  }
}