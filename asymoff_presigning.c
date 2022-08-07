#include "asymoff_presigning.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

// TIME
#include <time.h>

clock_t presigning_start_time, presigning_end_time;

static void start_timer() {
  presigning_start_time = clock();
}

static double get_time(const char* str) {
  presigning_end_time = clock();
  double diff_time = ((double)(presigning_end_time - presigning_start_time)) /CLOCKS_PER_SEC;
  if (str) {
    printf(str);
    printf("%f\n", diff_time);
  }

  return diff_time;
}

asymoff_presigning_data_t **asymoff_presigning_parties_new(asymoff_party_data_t ** const parties, uint64_t batch_size) 
{
  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec        = parties[0]->ec;

  asymoff_presigning_data_t **presign_parties = calloc(num_parties, sizeof(asymoff_presigning_data_t*));
  asymoff_presigning_data_t *party;
  
  for (uint64_t i = 0; i < num_parties; ++i) {

    presign_parties[i] = malloc(sizeof(asymoff_presigning_data_t));
    party = presign_parties[i];

    party->i = i;
    party->num_parties = num_parties;
    party->batch_size = batch_size;

    uint64_t aux_pos = 0;
    party->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->sid, sizeof(hash_chunk));
    zkp_aux_info_update_move(party->aux, &aux_pos, &party->i, sizeof(uint64_t));
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->srid, sizeof(hash_chunk));
    assert(party->aux->info_len == aux_pos);

    party->ec = ec;
    party->Y = parties[i]->Y;

    party->paillier_pub = parties[i]->paillier_pub;

    if (i == 0) {

      party->offline = malloc(sizeof(asymoff_presigning_data_offline_t));

      asymoff_presigning_data_offline_t *offline = party->offline;

      offline->H       = gr_el_array_new(batch_size, ec);
      offline->alpha   = scalar_array_new(batch_size);
      offline->phi_sch = zkp_schnorr_new(ec);

      party->msg_to_offline = malloc(sizeof(asymoff_presigning_msg_to_offline_t));
  
    } else { // i > 0

      party->online = malloc(sizeof(asymoff_presigning_data_online_t));

      asymoff_presigning_data_online_t *online = party->online;


      online->joint_B1 = gr_el_array_new(batch_size, ec);
    online->joint_B2 = gr_el_array_new(batch_size, ec);

      online->B1 = gr_el_array_new(batch_size, ec);
      online->B2 = gr_el_array_new(batch_size, ec);

      online->k  = scalar_array_new(batch_size);
      online->b  = scalar_array_new(batch_size);

      online->phi_ddh_anchor          = zkp_el_gamal_new(ec);
      online->phi_ddh_local_agg_proof = zkp_el_gamal_new(ec);
      online->phi_ddh_agg_proof       = zkp_el_gamal_new(ec);

      online->phi_ddh_anchor_secret.alpha  = scalar_new();
      online->phi_ddh_anchor_secret.lambda = scalar_new();

      party->in_msg_1 = calloc(num_parties, sizeof(asymoff_presigning_aggregate_msg_round_1_t));
      party->in_msg_2 = calloc(num_parties, sizeof(asymoff_presigning_aggregate_msg_round_2_t));
      party->in_msg_3 = calloc(num_parties, sizeof(asymoff_presigning_aggregate_msg_round_3_t));

      party->msg_from_offline = malloc(sizeof(asymoff_presigning_msg_from_offline_t));
    }
  }

  return presign_parties;
}

void asymoff_presigning_parties_free(asymoff_presigning_data_t **presign_parties)
{
  asymoff_presigning_data_t *party;

  uint64_t num_parties = presign_parties[0]->num_parties;
  uint64_t batch_size = presign_parties[0]->batch_size;

  for (uint64_t i = 0; i < num_parties; ++i) {
    party = presign_parties[i];

    zkp_aux_info_free(party->aux);
    
    if (i == 0) {

      asymoff_presigning_data_offline_t *offline = party->offline;

      zkp_schnorr_free(offline->phi_sch);
      
      gr_el_array_free(offline->H, batch_size);
      scalar_array_free(offline->alpha, batch_size);

      free(party->msg_to_offline);

      free(offline);
 
    } else { // i > 0

      asymoff_presigning_data_online_t *online = party->online;

      scalar_array_free(online->b, batch_size);
      scalar_array_free(online->k, batch_size);
      
      gr_el_array_free(online->B1, batch_size);
      gr_el_array_free(online->B2, batch_size);

       gr_el_array_free(online->joint_B1, batch_size);
       gr_el_array_free(online->joint_B2, batch_size);

      zkp_el_gamal_free(online->phi_ddh_anchor         );
      zkp_el_gamal_free(online->phi_ddh_local_agg_proof);
      zkp_el_gamal_free(online->phi_ddh_agg_proof      );

      scalar_free(online->phi_ddh_anchor_secret.alpha );
      scalar_free(online->phi_ddh_anchor_secret.lambda);

      free(party->in_msg_1);
      free(party->in_msg_2);  
      free(party->in_msg_3); 
      free(party->msg_from_offline);

      free(online);
    }

    
    free(party);
  }

  free(presign_parties);
}

void asymoff_presigning_aggregate_round_1_hash(hash_chunk hash, asymoff_presigning_aggregate_msg_round_2_t *msg_2, uint64_t batch_size, zkp_aux_info_t * const aux, ec_group_t ec) {

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, aux->info, aux->info_len);
  
  uint8_t *temp_bytes = malloc(2*PAILLIER_MODULUS_BYTES);

  for (uint64_t l = 0; l < batch_size; ++l) {
    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->B1[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->B2[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->phi_ddh_anchor->A1, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->phi_ddh_anchor->A2, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  SHA512_Update(&sha_ctx, msg_2->u, sizeof(hash_chunk));
  SHA512_Final(hash, &sha_ctx);

  free(temp_bytes);
}

int asymoff_presigning_aggregate_execute_round_1(asymoff_presigning_data_t *party) {

  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Aggregate Round 1\n", party->i);

  asymoff_presigning_data_online_t *online = party->online;
  uint64_t batch_size = party->batch_size;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = party->ec;

  start_timer();

  for (uint64_t l = 0; l < batch_size; ++l) {
  
    scalar_sample_in_range(online->k[l], ec_group_order(party->ec), 0, bn_ctx);
    scalar_sample_in_range(online->b[l], ec_group_order(party->ec), 0, bn_ctx);
  }
  get_time("Sampling k,b: ");

  for (uint64_t l = 0; l < batch_size; ++l) {
    group_operation(online->B1[l], NULL, online->b[l], NULL, NULL, ec, bn_ctx);
    group_operation(online->B2[l], NULL, online->k[l], party->Y, online->b[l], ec, bn_ctx);
  }
  get_time("computing all B1/2: ");

  zkp_el_gamal_public_t pi_ddh_public;
  pi_ddh_public.batch_size  = batch_size;
  pi_ddh_public.ec = party->ec;
  pi_ddh_public.Y  = party->Y;
  
  zkp_el_gamal_anchor(online->phi_ddh_anchor, &online->phi_ddh_anchor_secret, &pi_ddh_public);

  RAND_bytes(online->u, sizeof(hash_chunk));

  asymoff_presigning_aggregate_msg_round_2_t msg_2;
  msg_2.B1 = online->B1;
  msg_2.B2 = online->B2;
  msg_2.phi_ddh_anchor = online->phi_ddh_anchor;
  msg_2.u = &online->u;

  asymoff_presigning_aggregate_round_1_hash(online->T, &msg_2, batch_size, party->aux, ec);

  BN_CTX_free(bn_ctx);

  return 0;
}

uint64_t asymoff_presigning_aggregate_send_msg_1(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_aggregate_msg_round_1_t *in_msg_1 = &receiver->in_msg_1[sender->i];

  in_msg_1->T = &sender->online->T;

  return sizeof(hash_chunk);
}

int asymoff_presigning_aggregate_execute_round_2(asymoff_presigning_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Aggregate Round 2\n", party->i);

  asymoff_presigning_data_online_t *online = party->online;

  // For convinience
  party->in_msg_1[party->i].T = &online->T;

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t j = 1; j < party->num_parties; ++j) {
    SHA512_Update(&sha_ctx, *party->in_msg_1[j].T, sizeof(hash_chunk));
  }
  SHA512_Final(online->echo_all_T, &sha_ctx);

  return 0;
}

uint64_t asymoff_presigning_aggregate_send_msg_2(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_data_online_t *online = sender->online;

  asymoff_presigning_aggregate_msg_round_2_t *in_msg_2 = &receiver->in_msg_2[sender->i];

  in_msg_2->phi_ddh_anchor = online->phi_ddh_anchor;

  in_msg_2->B1  = online->B1;
  in_msg_2->B2  = online->B2;

  in_msg_2->u = &online->u;
  in_msg_2->echo_all_T = &online->echo_all_T;

  return zkp_el_gamal_anchor_bytelen() + sender->batch_size*2*GROUP_ELEMENT_BYTES + 2*sizeof(hash_chunk);
}

int asymoff_presigning_aggregate_execute_round_3(asymoff_presigning_data_t *party) {
  if (party->i == 0) return 1;

  uint64_t num_parties = party->num_parties;
  uint64_t batch_size = party->batch_size;

  asymoff_presigning_data_online_t *online = party->online;

  pinfo("Player %ld: Executing Aggregate Round 3\n", party->i);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  hash_chunk computed_T;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_presigning_aggregate_msg_round_2_t *in_msg_2 = &party->in_msg_2[j];

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));
    asymoff_presigning_aggregate_round_1_hash(computed_T, in_msg_2, batch_size, party->aux, party->ec);

    if (memcmp(computed_T, *party->in_msg_1[j].T, sizeof(hash_chunk)) != 0) {
      printf("Bad decommitment of previous round. Received from party %ld\n", j);
      return 1;
    }

    // Verify echo broadcast from others is same
    if (memcmp(online->echo_all_T, in_msg_2->echo_all_T, sizeof(hash_chunk)) != 0) {
      printf("Echo broadcast equality failure. Received from party %ld\n", j);
      return 1;
    }
  }

  start_timer();
  for (uint64_t l = 0; l < batch_size; ++l)
  {
    EC_POINT_copy(online->joint_B1[l], online->B1[l]);
    EC_POINT_copy(online->joint_B2[l], online->B2[l]);
    
    for (uint64_t j = 1; j < num_parties; ++j)
    {
      if (party->i == j) continue;
      
      EC_POINT_add(party->ec, online->joint_B1[l], online->joint_B1[l], party->in_msg_2[j].B1[l], bn_ctx);
      EC_POINT_add(party->ec, online->joint_B2[l], online->joint_B2[l], party->in_msg_2[j].B2[l], bn_ctx);
    }
  }
  get_time("Computinf joint B1/2: ");

  // Aggregate Proofs

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  zkp_el_gamal_proof_t  **phi_ddh_anchors = calloc(num_parties-1, sizeof(zkp_el_gamal_proof_t*));
  
  // For convinience
  party->in_msg_2[party->i].phi_ddh_anchor = online->phi_ddh_anchor;

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    phi_ddh_anchors[j-1] = party->in_msg_2[j].phi_ddh_anchor;
  }

  zkp_el_gamal_public_t phi_ddh_agg_public;
  phi_ddh_agg_public.batch_size = batch_size;
  phi_ddh_agg_public.ec = party->ec;
  phi_ddh_agg_public.Y  = party->Y;
  phi_ddh_agg_public.B1 = online->joint_B1;
  phi_ddh_agg_public.B2 = online->joint_B2;

  online->phi_ddh_anchor_secret.b = online->b;
  online->phi_ddh_anchor_secret.k = online->k;
  
  zkp_el_gamal_aggregate_anchors(online->phi_ddh_local_agg_proof, phi_ddh_anchors, num_parties-1);
  zkp_el_gamal_prove(online->phi_ddh_local_agg_proof, &online->phi_ddh_anchor_secret, &phi_ddh_agg_public, party->aux);

  free(phi_ddh_anchors);

  return 0;
}

uint64_t asymoff_presigning_aggregate_send_msg_3(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_data_online_t *online = sender->online;
  asymoff_presigning_aggregate_msg_round_3_t *in_msg_3 = &receiver->in_msg_3[sender->i];

  in_msg_3->phi_ddh_local_agg_proof = online->phi_ddh_local_agg_proof;

  return zkp_el_gamal_proof_bytelen();
}


int asymoff_presigning_aggregate_execute_final  (asymoff_presigning_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Aggregate Finalization\n", party->i);

  uint64_t num_parties = party->num_parties;
  asymoff_presigning_data_online_t *online = party->online;

  // Aggregate local proofs to a single proof and verify it

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  // For convinience
  party->in_msg_3[party->i].phi_ddh_local_agg_proof = online->phi_ddh_local_agg_proof;

  zkp_el_gamal_proof_t **phi_ddh_local_proofs = calloc(num_parties-1, sizeof(zkp_el_gamal_proof_t*));

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    phi_ddh_local_proofs[j-1] = party->in_msg_3[j].phi_ddh_local_agg_proof;
  }
  
  zkp_el_gamal_copy_anchor(online->phi_ddh_agg_proof, online->phi_ddh_local_agg_proof);
  zkp_el_gamal_aggregate_local_proofs(online->phi_ddh_agg_proof, phi_ddh_local_proofs, num_parties-1);
  
  zkp_el_gamal_public_t phi_ddh_agg_public;
  phi_ddh_agg_public.batch_size = party->batch_size;
  phi_ddh_agg_public.ec = party->ec;
  phi_ddh_agg_public.Y  = party->Y;
  phi_ddh_agg_public.B1 = online->joint_B1;
  phi_ddh_agg_public.B2 = online->joint_B2;

  if (zkp_el_gamal_verify(online->phi_ddh_agg_proof, &phi_ddh_agg_public, party->aux) != 1) {
    printf("Aggregated ZKP El Gamal verification for B failed.\n");
    return 1;
  }

  free(phi_ddh_local_proofs);

  return 0;
}

uint64_t asymoff_presigning_send_msg_to_offline(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i != 0) return 0;

  asymoff_presigning_data_online_t *online = sender->online;
  asymoff_presigning_msg_to_offline_t *in_msg = receiver->msg_to_offline;

  in_msg->aggregator_i = sender->i;

  in_msg->phi_ddh_agg_proof = online->phi_ddh_agg_proof;
  in_msg->joint_B1 = online->joint_B1;
  in_msg->joint_B2 = online->joint_B2;
  
  return sender->batch_size*2*GROUP_ELEMENT_BYTES + zkp_el_gamal_proof_bytelen();
}

int asymoff_presigning_execute_offline (asymoff_presigning_data_t *party) {
  if (party->i != 0) return 0;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t num_parties = party->num_parties;
  uint64_t batch_size = party->batch_size;

  asymoff_presigning_data_offline_t *offline = party->offline;

  asymoff_presigning_msg_to_offline_t *in_msg = party->msg_to_offline;

  zkp_el_gamal_public_t phi_ddh_agg_public;
  phi_ddh_agg_public.batch_size = party->batch_size;
  phi_ddh_agg_public.ec = party->ec;
  phi_ddh_agg_public.Y  = party->Y;
  phi_ddh_agg_public.B1 = in_msg->joint_B1;
  phi_ddh_agg_public.B2 = in_msg->joint_B2;
  
  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  if (zkp_el_gamal_verify(in_msg->phi_ddh_agg_proof, &phi_ddh_agg_public, party->aux) != 1) {
    printf("Aggregated ZKP El Gamal verification for B failed.\n");
    return 1;
  }

  for (uint64_t l = 0; l < batch_size; ++l) {
    scalar_sample_in_range(offline->alpha[l], ec_group_order(party->ec), 0, bn_ctx);
    group_operation(offline->H[l], NULL, NULL, ec_group_generator(party->ec), offline->alpha[l], party->ec, bn_ctx);
  }
    
  zkp_schnorr_public_t phi_sch_public;
  phi_sch_public.batch_size  = party->batch_size;
  phi_sch_public.ec   = party->ec;
  phi_sch_public.X    = offline->H;

  zkp_schnorr_secret_t phi_sch_secret;
  phi_sch_secret.a = scalar_new();
  phi_sch_secret.x     = offline->alpha;

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
  zkp_schnorr_anchor(offline->phi_sch, &phi_sch_secret, &phi_sch_public);
  zkp_schnorr_prove(offline->phi_sch, &phi_sch_secret, &phi_sch_public, party->aux);

  scalar_free(phi_sch_secret.a);
  BN_CTX_free(bn_ctx);

  return 0;
}

uint64_t asymoff_presigning_send_msg_from_offline (asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i != 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_data_offline_t *offline = sender->offline;
  asymoff_presigning_msg_from_offline_t *in_msg = receiver->msg_from_offline;

  in_msg->H       = offline->H;
  in_msg->phi_sch = offline->phi_sch;
  
  return sender->batch_size * GROUP_ELEMENT_BYTES + zkp_schnorr_proof_bytelen();
}

int asymoff_presigning_export_data(asymoff_party_data_t **parties, asymoff_presigning_data_t ** const presign_parties) {

  uint64_t num_parties  = parties[0]->num_parties;
  uint64_t party_0_i = 0;

  asymoff_presigning_data_t *party;

  for (uint64_t i = 1; i < num_parties; ++i) {

    party = presign_parties[i];

    zkp_schnorr_public_t phi_sch_public;
    phi_sch_public.batch_size = party->batch_size;
    phi_sch_public.ec         = party->ec;
    phi_sch_public.X          = party->msg_from_offline->H;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party_0_i, sizeof(uint64_t));

    if (zkp_schnorr_verify(party->msg_from_offline->phi_sch, &phi_sch_public, party->aux) != 1) {
      printf("ZKP Schnorr verification for H failed, during data export.\n");
      return 1;
    }

    for (uint64_t l = 0; l < party->batch_size; ++l) {
      if (group_elem_is_ident(party->msg_from_offline->H[l], party->ec) == 1) {
        printf("Invalid identity element for H #%ld, during data export.\n", l);
        return 1;
      }
    }
  }

  party = presign_parties[0];
  asymoff_presigning_msg_to_offline_t *to_offline = party->msg_to_offline;

  parties[0]->batch_size = party->batch_size;
  parties[0]->next_index = 0;
  parties[0]->curr_index = 0;

  gr_el_array_copy(parties[0]->joint_B1, to_offline->joint_B1, party->batch_size);
  gr_el_array_copy(parties[0]->joint_B2, to_offline->joint_B2, party->batch_size);
  gr_el_array_copy(parties[0]->H, party->offline->H, party->batch_size);
  scalar_array_copy(parties[0]->nonce, party->offline->alpha, party->batch_size);

  for (uint64_t i = 1; i < num_parties; ++i) {
    
    party = presign_parties[i];

    parties[i]->batch_size = party->batch_size;
    parties[i]->next_index = 0;
    parties[i]->curr_index = 0;
    
    scalar_array_copy(parties[i]->b, presign_parties[i]->online->b, party->batch_size);
    scalar_array_copy(parties[i]->nonce, presign_parties[i]->online->k, party->batch_size);
    gr_el_array_copy (parties[i]->H, party->msg_from_offline->H, party->batch_size);
    
  // // For convinience
  party->in_msg_2[party->i].B1 = party->online->B1;
  party->in_msg_2[party->i].B2 = party->online->B2;

    for (uint64_t j = 1; j < num_parties; ++j) {
      gr_el_array_copy(parties[i]->B1[j], party->in_msg_2[j].B1, party->batch_size);
      gr_el_array_copy(parties[i]->B2[j], party->in_msg_2[j].B2, party->batch_size);
    }
  }

  return 0;
}
