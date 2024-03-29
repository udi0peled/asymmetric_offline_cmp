#include "asymoff_key_generation.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>

asymoff_key_gen_data_t **asymoff_key_gen_parties_new(asymoff_party_data_t ** const parties)
{
  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec = parties[0]->ec;
  
  asymoff_key_gen_data_t **kgd_parties = calloc(num_parties, sizeof(asymoff_key_gen_data_t*));

  for (uint64_t i = 0; i < num_parties; ++i) {
    kgd_parties[i] = malloc(sizeof(asymoff_key_gen_data_t));

    memcpy(kgd_parties[i]->sid, parties[i]->sid, sizeof(hash_chunk));
    kgd_parties[i]->i = i;
    kgd_parties[i]->num_parties = num_parties;

    kgd_parties[i]->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
    memset(kgd_parties[i]->aux->info, 0x00, kgd_parties[i]->aux->info_len);

    kgd_parties[i]->ec = ec;

    kgd_parties[i]->x = parties[i]->x;
    kgd_parties[i]->X = group_elem_new(ec);

    kgd_parties[i]->y = scalar_new();
    kgd_parties[i]->Y = group_elem_new(ec);

    kgd_parties[i]->paillier_priv = paillier_encryption_private_new();
    kgd_parties[i]->paillier_pub = paillier_encryption_public_new();

    kgd_parties[i]->rped_priv = ring_pedersen_private_new();
    kgd_parties[i]->rped_pub = ring_pedersen_public_new();

    kgd_parties[i]->psi_sch_anchor = zkp_schnorr_new(ec);
    kgd_parties[i]->psi_sch_proof  = zkp_schnorr_new(ec);
    kgd_parties[i]->psi_sch_secret.a = scalar_new();

    kgd_parties[i]->psi_paillier = zkp_paillier_blum_new();
    kgd_parties[i]->psi_rped     = zkp_ring_pedersen_param_new();
    kgd_parties[i]->psi_factors  = calloc(num_parties, sizeof(zkp_no_small_factors_t*));
    
    for (uint64_t j = 0; j < num_parties; ++j) {
      if (i == j) continue;
       kgd_parties[i]->psi_factors[j] = zkp_no_small_factors_new();
    }

    kgd_parties[i]->in_msg_1 = calloc(num_parties, sizeof(asymoff_key_gen_msg_round_1_t));
    kgd_parties[i]->in_msg_2 = calloc(num_parties, sizeof(asymoff_key_gen_msg_round_2_t));
    kgd_parties[i]->in_msg_3 = calloc(num_parties, sizeof(asymoff_key_gen_msg_round_3_t));
    kgd_parties[i]->in_msg_4 = calloc(num_parties, sizeof(asymoff_key_gen_msg_round_4_t));
  }
  
  kgd_parties[0]->W_0 = scalar_new();
  kgd_parties[0]->pi_tight  = calloc(num_parties, sizeof(zkp_tight_range_proof_t));
  
  for (uint64_t j = 1; j < num_parties; ++j) {
    kgd_parties[0]->pi_tight[j]  = zkp_tight_range_new();
  }

  return kgd_parties;
}

void asymoff_key_gen_parties_free(asymoff_key_gen_data_t **kgd_parties)
{

  uint64_t num_parties = kgd_parties[0]->num_parties;

  scalar_free(kgd_parties[0]->W_0);

  for (uint64_t j= 1; j < num_parties; ++j) {
    zkp_tight_range_free(kgd_parties[0]->pi_tight[j]);
  }
  free(kgd_parties[0]->pi_tight);

  for (uint64_t i = 0; i < num_parties; ++i) {
  
    group_elem_free(kgd_parties[i]->X);
    scalar_free(kgd_parties[i]->y);
    group_elem_free(kgd_parties[i]->Y);
    paillier_encryption_free_keys(kgd_parties[i]->paillier_priv, kgd_parties[i]->paillier_pub);
  
    ring_pedersen_free_param(kgd_parties[i]->rped_priv, kgd_parties[i]->rped_pub);

    zkp_schnorr_free(kgd_parties[i]->psi_sch_anchor);
    zkp_schnorr_free(kgd_parties[i]->psi_sch_proof);
    scalar_free(kgd_parties[i]->psi_sch_secret.a);

    zkp_paillier_blum_free(kgd_parties[i]->psi_paillier);
    zkp_ring_pedersen_param_free(kgd_parties[i]->psi_rped);
    
    for (uint64_t j = 0; j < num_parties; ++j) {
      if (i == j) continue;
       zkp_no_small_factors_free(kgd_parties[i]->psi_factors[j]);
    }
    free(kgd_parties[i]->psi_factors);
    
    free(kgd_parties[i]->in_msg_1);
    free(kgd_parties[i]->in_msg_2);
    free(kgd_parties[i]->in_msg_3);
    free(kgd_parties[i]->in_msg_4);

    zkp_aux_info_free(kgd_parties[i]->aux);
    
    free(kgd_parties[i]);
  }

  free(kgd_parties);
}

void asymoff_key_gen_round_1_hash(hash_chunk hash, asymoff_key_gen_msg_round_2_t * const msg_2, uint64_t sender_i, hash_chunk sid, ec_group_t ec) {

  uint64_t rped_pub_byteln = ring_pedersen_public_bytelen(RING_PED_MODULUS_BYTES);
  uint8_t *temp_bytes = malloc(PAILLIER_MODULUS_BYTES + rped_pub_byteln);
  
  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, sid, sizeof(hash_chunk));
  SHA512_Update(&sha_ctx, &sender_i, sizeof(uint64_t));
  SHA512_Update(&sha_ctx, *msg_2->srid, sizeof(hash_chunk));
  
  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->X, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->Y, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->psi_sch_anchor->A, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  scalar_to_bytes(&temp_bytes, PAILLIER_MODULUS_BYTES, msg_2->paillier_pub->N, 0);
  SHA512_Update(&sha_ctx, temp_bytes, PAILLIER_MODULUS_BYTES);

  ring_pedersen_public_to_bytes(&temp_bytes, &rped_pub_byteln, msg_2->rped_pub, RING_PED_MODULUS_BYTES, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  SHA512_Update(&sha_ctx, *msg_2->u, sizeof(hash_chunk));
  SHA512_Final(hash, &sha_ctx);
  
  free(temp_bytes);
}

int asymoff_key_gen_execute_round_1(asymoff_key_gen_data_t *party) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = party->ec;

  pinfo("Player %ld: Executing Round 1\n", party->i);

  group_operation(party->X, NULL, party->x, NULL, NULL, ec, bn_ctx);

  scalar_sample_in_range(party->y, ec_group_order(ec), 0, bn_ctx);
  group_operation(party->Y, NULL, party->y, NULL, NULL, ec, bn_ctx);

  zkp_schnorr_public_t psi_sch_public;
  psi_sch_public.batch_size = 1;
  psi_sch_public.ec = ec;

  zkp_schnorr_anchor(party->psi_sch_anchor, &party->psi_sch_secret, &psi_sch_public);

  paillier_encryption_generate_private(party->paillier_priv, 4*PAILLIER_MODULUS_BYTES);
  paillier_encryption_copy_keys(NULL, party->paillier_pub, party->paillier_priv, NULL);

  ring_pedersen_generate_private(party->rped_priv, 4*RING_PED_MODULUS_BYTES);
  ring_pedersen_copy_param(NULL, party->rped_pub, party->rped_priv, NULL);

  RAND_bytes(party->srid, sizeof(hash_chunk));
  RAND_bytes(party->u, sizeof(hash_chunk));

  // Temporarily generate future decomitment to hash, in order to commit
  asymoff_key_gen_msg_round_2_t msg_2;
  msg_2.psi_sch_anchor = party->psi_sch_anchor;
  msg_2.srid = &party->srid;
  msg_2.X = party->X;
  msg_2.Y = party->Y;
  msg_2.paillier_pub = party->paillier_pub;
  msg_2.rped_pub = party->rped_pub;
  msg_2.u = &party->u;

  asymoff_key_gen_round_1_hash(party->V, &msg_2, party->i, party->sid, ec);

  BN_CTX_free(bn_ctx);

  return 0;
}

uint64_t asymoff_key_gen_send_msg_1(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver) {
  
  asymoff_key_gen_msg_round_1_t *in_msg_1 = &receiver->in_msg_1[sender->i];
  
  in_msg_1->V = &sender->V;

  return sizeof(hash_chunk);
}

int asymoff_key_gen_execute_round_2(asymoff_key_gen_data_t *party) {
  pinfo("Player %ld: Executing Round 2\n", party->i);

  // For convinience, set in_msg_1 V for self as outgoing V
  party->in_msg_1[party->i].V = &party->V;

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t j = 0; j < party->num_parties; ++j) {
    SHA512_Update(&sha_ctx, *party->in_msg_1[j].V, sizeof(hash_chunk));
  }
  SHA512_Final(party->echo_all_V, &sha_ctx);

  return 0;
}

uint64_t asymoff_key_gen_send_msg_2(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver) {

  asymoff_key_gen_msg_round_2_t *in_msg_2 = &receiver->in_msg_2[sender->i];

  in_msg_2->psi_sch_anchor = sender->psi_sch_anchor;
  in_msg_2->srid = &sender->srid;
  in_msg_2->X = sender->X;
  in_msg_2->Y = sender->Y;
  in_msg_2->paillier_pub = sender->paillier_pub;
  in_msg_2->rped_pub = sender->rped_pub;
  in_msg_2->u = &sender->u;
  in_msg_2->echo_all_V = &sender->echo_all_V;

  return 3*GROUP_ELEMENT_BYTES + PAILLIER_MODULUS_BYTES + (RING_PEDERSEN_MULTIPLICITY + 2)*RING_PED_MODULUS_BYTES + 3*sizeof(hash_chunk);
}


int asymoff_key_gen_execute_round_3(asymoff_key_gen_data_t *party) {
  pinfo("Player %ld: Executing Round 3\n", party->i);

  hash_chunk computed_V;

  // Initialize joint srid to self, later will xor with rest
  memcpy(party->joint_srid, party->srid, sizeof(hash_chunk));

  // Validate data recevied from others
  for (uint64_t j = 0; j < party->num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_key_gen_msg_round_2_t *in_msg_2 = &party->in_msg_2[j];
    asymoff_key_gen_round_1_hash(computed_V, in_msg_2, j, party->sid, party->ec);

    if (memcmp(computed_V, party->in_msg_1[j].V, sizeof(hash_chunk)) != 0) {
      printf("Bad decommitment of previous round. Received from party %ld\n", j);
      return 1;
    }

    // Verify echo broadcast from others is same
    if (memcmp(party->echo_all_V, in_msg_2->echo_all_V, sizeof(hash_chunk)) != 0) {
      printf("Echo broadcast equality failure. Received from party %ld\n", j);
      return 1;
    }

    // Verify Paillier public key is lengthy
    if (8*PAILLIER_MODULUS_BYTES - 1 > scalar_bitlength(in_msg_2->paillier_pub->N)) {
      printf("Paillier public key too short. Received from party %ld\n", j);
      return 1;
    }

    // Verify Ring Pedersen public key is lengthy (and co-prime to t)
     if (8*RING_PED_MODULUS_BYTES - 1 >  scalar_bitlength(in_msg_2->rped_pub->N)) {
      printf("Ring-Pedersen public modulus too short. Received from party %ld\n", j);
      return 1;
    }
    
    BN_CTX *bn_ctx = BN_CTX_secure_new();

    if (scalar_coprime(in_msg_2->rped_pub->N, in_msg_2->rped_pub->t, bn_ctx) != 1) {
      printf("Ring-Pedersen public modulus and t not co-prime. Received from party %ld\n", j);
      return 1;
    }
    BN_CTX_free(bn_ctx);

    // xor srid with all others
    for (uint64_t pos = 0; pos < sizeof(hash_chunk); ++pos) party->joint_srid[pos] ^= (*in_msg_2->srid)[pos];
  }

  // Aux Info (ssid, i, srid) - First time
  uint64_t aux_pos = 0;
  zkp_aux_info_update_move(party->aux, &aux_pos, party->sid, sizeof(hash_chunk));
  zkp_aux_info_update_move(party->aux, &aux_pos, &party->i, sizeof(uint64_t));
  zkp_aux_info_update_move(party->aux, &aux_pos, party->joint_srid, sizeof(hash_chunk));
  assert(party->aux->info_len == aux_pos);

  // Set Schnorr ZKP public claim and secret, then prove

  zkp_schnorr_public_t psi_sch_public;
  psi_sch_public.batch_size = 1;
  psi_sch_public.ec = party->ec;
  psi_sch_public.X = &party->X;
  
  party->psi_sch_secret.x = &party->x;

  zkp_schnorr_copy_anchor(party->psi_sch_proof, party->psi_sch_anchor);
  zkp_schnorr_prove(party->psi_sch_proof, &party->psi_sch_secret, &psi_sch_public, party->aux);

  // ZKP for muduli
  zkp_paillier_blum_prove(party->psi_paillier, party->paillier_priv, party->aux);
  zkp_ring_pedersen_param_prove(party->psi_rped, party->rped_priv, party->aux);

  return 0;
}

uint64_t asymoff_key_gen_send_msg_3(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver) {
  asymoff_key_gen_msg_round_3_t *in_msg_3 = &receiver->in_msg_3[sender->i];

  in_msg_3->psi_sch_proof = sender->psi_sch_proof;
  in_msg_3->psi_paillier = sender->psi_paillier;
  in_msg_3->psi_rped = sender->psi_rped;

  return zkp_schnorr_proof_bytelen() + zkp_paillier_blum_proof_bytelen() + zkp_ring_pedersen_param_proof_bytelen();
}

int asymoff_key_gen_execute_round_4(asymoff_key_gen_data_t *party) {
  pinfo("Player %ld: Executing Round 4\n", party->i);

  zkp_schnorr_public_t psi_sch_public;
  psi_sch_public.batch_size = 1;
  psi_sch_public.ec = party->ec;

  // Validate data recevied from others
  for (uint64_t j = 0; j < party->num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_key_gen_msg_round_3_t *in_msg_3 = &party->in_msg_3[j];
   
    zkp_schnorr_copy_anchor(in_msg_3->psi_sch_proof, party->in_msg_2[j].psi_sch_anchor);

    // Verify Schnorr ZKP
    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));      // Update j to proving player
    psi_sch_public.X = &party->in_msg_2[j].X;

    if (zkp_schnorr_verify(in_msg_3->psi_sch_proof, &psi_sch_public, party->aux) != 1) {
      printf("Schnorr ZKP verification failed. Received from party %ld\n", j);
      return 1;
    }

    if (zkp_paillier_blum_verify(in_msg_3->psi_paillier, party->in_msg_2[j].paillier_pub, party->aux) != 1) {
      printf("Paillier-Blum ZKP verification failed. Received from party %ld\n", j);
      return 1;
    }
    
    if (zkp_ring_pedersen_param_verify(in_msg_3->psi_rped, party->in_msg_2[j].rped_pub, party->aux) != 1) {
      printf("Ring-Pedersen ZKP verification failed. Received from party %ld\n", j);
      return 1;
    }

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));      // Update j to proving player
    // Generate no-small-factors ZKP for party j
    zkp_no_small_factors_prove(party->psi_factors[j], party->paillier_priv, party->in_msg_2[j].rped_pub, party->aux);
  }
  
  // Offline party gives more data with creates tight range proof
  if (party->i == 0) {
    
    scalar_t rho = scalar_new();

    paillier_encryption_sample(rho, party->paillier_pub);
    paillier_encryption_encrypt(party->W_0, party->x, rho, party->paillier_pub);
    
    // Create tight proof for each party (using its Ring-Pedersen modulus)

    zkp_tight_range_positive_splitting_t *splitting = zkp_tight_range_splitting_new(party->x);

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));      // Update i to proving player

    for (uint64_t j = 1; j < party->num_parties; ++j) {

      zkp_tight_range_public_t pi_public;
      pi_public.ec = party->ec;
      pi_public.paillier_pub = party->paillier_pub;
      pi_public.rped_pub =  party->in_msg_2[j].rped_pub;;
      pi_public.W   = party->W_0;
      pi_public.X   = party->X;

      zkp_tight_range_secret_t pi_secret;
      pi_secret.rho       = rho;
      pi_secret.x         = party->x;
      pi_secret.splitting = splitting; 
    
      zkp_tight_range_prove(party->pi_tight[j], &pi_secret, &pi_public, party->aux);
    }
    
    zkp_tight_range_splitting_free(splitting);
    scalar_free(rho);
  }

  return 0;
}

uint64_t asymoff_key_gen_send_msg_4(asymoff_key_gen_data_t *sender, asymoff_key_gen_data_t *receiver) {
  asymoff_key_gen_msg_round_4_t *in_msg_4 = &receiver->in_msg_4[sender->i];
  in_msg_4->psi_factors = sender->psi_factors[receiver->i];

  in_msg_4->pi_tight = NULL;
  in_msg_4->W_0 = NULL;

  if (sender->i == 0) {
    
    in_msg_4->pi_tight = sender->pi_tight[receiver->i];
    in_msg_4->W_0 = sender->W_0;
    
    //TODO: Broadcast W_0?

    return 2*PAILLIER_MODULUS_BYTES + zkp_no_small_factors_proof_bytelen() + zkp_tight_range_proof_bytelen()*(sender->num_parties - 1);
  }

  return zkp_no_small_factors_proof_bytelen();
}


int asymoff_key_gen_execute_final(asymoff_key_gen_data_t *party) {
  pinfo("Player %ld: Executing Finalization\n", party->i);

  // Validate data recevied from others
  for (uint64_t j = 0; j < party->num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_key_gen_msg_round_4_t *in_msg_4 = &party->in_msg_4[j];

    // Verify Schnorr ZKP
    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));      // Update j to proving player
    if (zkp_no_small_factors_verify(in_msg_4->psi_factors, party->in_msg_2[j].paillier_pub, party->rped_pub, party->aux) != 1) {
      printf("No Small Factors ZKP verification failed. Received from party %ld\n", j);
      return 1;
    }
  }
  
  if (party->i != 0) {
    
    uint64_t party_0_i = 0;
    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party_0_i, sizeof(uint64_t));      // Update i to proving player

    zkp_tight_range_public_t pi_public;
    pi_public.ec = party->ec;
    pi_public.paillier_pub = party->in_msg_2[0].paillier_pub;
    pi_public.rped_pub = party->rped_pub;
    pi_public.W   = party->in_msg_4[0].W_0;
    pi_public.X   = party->in_msg_2[0].X;

    if (zkp_tight_range_verify(party->in_msg_4[0].pi_tight, &pi_public, party->aux) != 1) {
      printf("Tight Range ZKP verification failed. Received from party %d\n", 0);
      return 1;
    }
  }

  return 0;
}

void asymoff_key_gen_export_data(asymoff_party_data_t **parties, asymoff_key_gen_data_t ** const kgd_parties) {
  uint64_t num_parties = parties[0]->num_parties;
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  // Compute joint Y
  ec_group_t ec = parties[0]->ec;
  for (uint64_t i = 1; i < num_parties; ++i) {
    group_operation(parties[0]->Y, parties[0]->Y, NULL, kgd_parties[0]->in_msg_2[i].Y, NULL, ec, bn_ctx);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {

    asymoff_party_data_t *party = parties[i];
    const asymoff_key_gen_data_t *kgd = kgd_parties[i];

    memcpy(party->srid, kgd->joint_srid, sizeof(hash_chunk));
    scalar_copy(party->x, kgd->x);

    if (i == 0) {
      scalar_copy(party->W_0, kgd->W_0);
    } else {
      scalar_copy(party->W_0, kgd->in_msg_4[0].W_0);
    }
    group_elem_copy(party->Y, parties[0]->Y);

    paillier_encryption_copy_keys(party->paillier_priv, NULL, kgd->paillier_priv, NULL);
    ring_pedersen_copy_param(party->rped_priv, NULL, kgd->rped_priv, NULL);

    // For easy of copy
    kgd->in_msg_2[i].X            = kgd->X;
    kgd->in_msg_2[i].rped_pub     = kgd->rped_pub;
    kgd->in_msg_2[i].paillier_pub = kgd->paillier_pub;

    for (uint64_t j = 0; j < num_parties; ++j) {
      paillier_encryption_copy_keys(NULL, party->paillier_pub[j], NULL, kgd->in_msg_2[j].paillier_pub);
      ring_pedersen_copy_param(NULL, party->rped_pub[j], NULL, kgd->in_msg_2[j].rped_pub);
      group_elem_copy(party->X[j], kgd->in_msg_2[j].X);
    }
  }

  BN_CTX_free(bn_ctx);
}


void asymoff_key_gen_mock_export_data(asymoff_party_data_t **parties) {
  
  asymoff_party_data_t *party;

  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec = parties[0]->ec;

  hash_chunk srid;
  gr_elem_t Y   = group_elem_new(ec);
  scalar_t *x   = scalar_array_new(num_parties);
  scalar_t W_0  = scalar_new();
  scalar_t rho  = scalar_new();
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_sample_in_range(rho, ec_group_order(ec), 0, bn_ctx);
  group_operation(Y, NULL, rho, NULL, NULL, ec, bn_ctx);
  
  RAND_bytes(srid, sizeof(hash_chunk));

  for (uint64_t i = 0; i < num_parties; ++i) {
    
    party = parties[i];

    group_elem_copy(party->Y, Y);
    memcpy(party->srid, srid, sizeof(hash_chunk));
        
    scalar_sample_in_range(x[i], ec_group_order(ec), 0, bn_ctx);
    scalar_copy(party->x, x[i]);
    group_operation(party->X[i], NULL, x[i], NULL, NULL, ec, bn_ctx);

    paillier_encryption_generate_private(party->paillier_priv, 4*PAILLIER_MODULUS_BYTES);
    paillier_encryption_copy_keys(NULL, party->paillier_pub[i], party->paillier_priv, NULL);

    ring_pedersen_generate_private(party->rped_priv, 4*RING_PED_MODULUS_BYTES);
    ring_pedersen_copy_param(NULL, party->rped_pub[i], party->rped_priv, NULL);
  }

  paillier_encryption_sample(rho, parties[0]->paillier_pub[0]);
  paillier_encryption_encrypt(W_0, x[0], rho, parties[0]->paillier_pub[0]);

  for (uint64_t i = 0; i < num_parties; ++i) {

    party = parties[i];

    scalar_copy(party->W_0, W_0);

    for (uint64_t j = 0; j < num_parties; ++j) {
      if (j == i) continue;
      paillier_encryption_copy_keys(NULL, party->paillier_pub[j], NULL, parties[j]->paillier_pub[j]);
      ring_pedersen_copy_param(NULL, party->rped_pub[j], NULL, parties[j]->rped_pub[j]);
      group_elem_copy(party->X[j], parties[j]->X[j]);
    }
  }

  group_elem_free(Y);
  scalar_array_free(x, num_parties);
  scalar_free(W_0);
  scalar_free(rho);
  BN_CTX_free(bn_ctx);
}
