#include "asymoff_protocol.h"

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
    
    if (i != 0) parties[i]->W_0 = scalar_new();
  
    for (uint64_t j = 0; j < num_parties; ++j) {
        parties[i]->X[j] = group_elem_new(ec);
        parties[i]->paillier_pub[j] = paillier_encryption_public_new();
        parties[i]->rped_pub[j] = ring_pedersen_public_new();
    }
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

    if (i != 0) scalar_free(parties[i]->W_0);
    scalar_free(parties[i]->x);
    group_elem_free(parties[i]->Y);
    paillier_encryption_free_keys(parties[i]->paillier_priv, NULL);
    ring_pedersen_free_param(parties[i]->rped_priv, NULL);
    ec_group_free(parties[i]->ec);

    free(parties[i]);
  }

  free(parties);
}

void asymoff_save_data_from_key_gen(asymoff_party_data_t **parties, asymoff_key_gen_data_t **kgd_parties) {
  uint64_t num_parties = parties[0]->num_parties;
  
  // Compute joint Y
  ec_group_t ec = parties[0]->ec;
  for (uint64_t i = 1; i < num_parties; ++i) {
    group_operation(parties[0]->Y, parties[0]->Y, kgd_parties[0]->in_msg_2[i].Y, NULL, ec);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {

    asymoff_party_data_t *party = parties[i];
    asymoff_key_gen_data_t *kgd = kgd_parties[i];

    memcpy(party->srid, kgd->joint_srid, sizeof(hash_chunk));
    scalar_copy(party->x, kgd->x);

    if (i != 0) scalar_copy(party->W_0, kgd->in_msg_4[0].W_0);
    group_elem_copy(party->Y, parties[0]->Y);

    paillier_encryption_copy_keys(party->paillier_priv, NULL, kgd->paillier_priv, NULL);
    ring_pedersen_copy_param(party->rped_priv, NULL, kgd->rped_priv, NULL);

    for (uint64_t j = 0; j < num_parties; ++j) {
      paillier_encryption_copy_keys(NULL, party->paillier_pub[j], NULL, kgd->in_msg_2[j].paillier_pub);
      ring_pedersen_copy_param(NULL, party->rped_pub[j], NULL, kgd->in_msg_2[j].rped_pub);
      group_elem_copy(party->X[j], kgd->in_msg_2[j].X);
    }
  }
}
