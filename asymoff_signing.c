#include "asymoff_signing.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

asymoff_signing_data_t **asymoff_signing_parties_new(asymoff_party_data_t ** parties, uint64_t num_sigs)  {
  
  uint64_t num_parties = parties[0]->num_parties;
  assert(num_parties >= 2);

  for (uint64_t i = 0; i < num_parties; ++i) {
    if (parties[i]->next_index + num_sigs > parties[i]->batch_size)
    {
      printf("Party %ld can't sign %ld signature. Batch size: %ld, next index: %ld.\n", num_sigs, i, parties[i]->batch_size, parties[i]->next_index);
      return NULL;
    }
  }
  
  asymoff_signing_data_t **signing_parties = calloc(num_parties, sizeof(asymoff_signing_data_t *));

  for (uint64_t i = 0; i < num_parties; ++i) {

    uint64_t next_index = parties[i]->next_index;
    ec_group_t ec = parties[i]->ec;

    signing_parties[i] = malloc(sizeof(asymoff_signing_data_t));

    asymoff_signing_data_t *party = signing_parties[i];
    
    party->i = i;
    party->num_parties = num_parties;
    party->num_sigs = num_sigs;

    party->ec = ec;
    party->gen = parties[i]->gen;
    party->Y = parties[i]->Y;

    party->x = parties[i]->x;
    party->X = parties[i]->X;

    party->online_X = group_elem_new(ec);
    group_operation(party->online_X, NULL ,NULL, NULL, ec);
    for (uint64_t i = 1; i < num_parties; ++i) group_operation(party->online_X, party->online_X, party->X[i], NULL, ec);
    
    party->paillier_pub = parties[i]->paillier_pub;
    party->rped_pub = parties[i]->rped_pub;

    uint64_t aux_pos = 0;
    party->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->sid, sizeof(hash_chunk));
    zkp_aux_info_update_move(party->aux, &aux_pos, &party->i, sizeof(uint64_t));
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->srid, sizeof(hash_chunk));
    assert(party->aux->info_len == aux_pos);

    party->R      = new_gr_el_array(num_sigs, ec);
    party->chi    = new_scalar_array(num_sigs);

    party->nonce  = &parties[i]->nonce[next_index];
    party->b      = &parties[i]->b[next_index];
    party->H      = &parties[i]->H[next_index];

    party->joint_B1 = parties[i]->joint_B1;
    party->joint_B2 = parties[i]->joint_B2;

    party->joint_V1 = new_gr_el_array(num_sigs, ec);
    party->joint_V2 = new_gr_el_array(num_sigs, ec);

    if (i != 0) {
      party->B1 = calloc(num_parties, sizeof(gr_elem_t *));
      party->B2 = calloc(num_parties, sizeof(gr_elem_t *));

      for (uint64_t j = 1; j < num_parties; ++j) {
        party->B1[j] = &parties[i]->B1[j][next_index];
        party->B2[j] = &parties[i]->B2[j][next_index];
      }

      party->V1 = new_gr_el_array(num_sigs, ec);
      party->V2 = new_gr_el_array(num_sigs, ec);

      party->W_0 = parties[i]->W_0;

      party->v = new_scalar_array(num_sigs);

      party->pi_eph_anchor          = zkp_el_gamal_dlog_new(num_sigs, ec);
      party->pi_eph_local_agg_proof = zkp_el_gamal_dlog_new(num_sigs, ec);
      
      party->pi_eph_agg_public.B1 = new_gr_el_array(num_sigs, party->ec);
      party->pi_eph_agg_public.B2 = new_gr_el_array(num_sigs, party->ec);

      party->pi_eph_anchor_secret.lambda = new_scalar_array(num_sigs);
      party->pi_eph_anchor_secret.rho    = new_scalar_array(num_sigs);


      party->pi_chi_anchor          = zkp_double_el_gamal_new(ec);
      party->pi_chi_local_agg_proof = zkp_double_el_gamal_new(ec);
      
      party->pi_chi_agg_public.B1 = new_gr_el_array(num_sigs, party->ec);
      party->pi_chi_agg_public.B2 = new_gr_el_array(num_sigs, party->ec);
      party->pi_chi_agg_public.V1 = new_gr_el_array(num_sigs, party->ec);
      party->pi_chi_agg_public.V2 = new_gr_el_array(num_sigs, party->ec);

      party->pi_chi_anchor_secret.alpha = scalar_new();
      party->pi_chi_anchor_secret.beta  = scalar_new();
      party->pi_chi_anchor_secret.gamma = scalar_new();

      
      party->in_online_msg_1 = calloc(num_parties, sizeof(asymoff_signing_online_msg_round_1_t));
      party->in_online_msg_2 = calloc(num_parties, sizeof(asymoff_signing_online_msg_round_2_t));
      party->in_online_msg_3 = calloc(num_parties, sizeof(asymoff_signing_online_msg_round_3_t));
      party->in_online_msg_4 = calloc(num_parties, sizeof(asymoff_signing_online_msg_round_4_t));

      party->in_aggregate_msg_1 = calloc(num_parties, sizeof(asymoff_signing_aggregate_msg_round_1_t));
      party->in_aggregate_msg_2 = calloc(num_parties, sizeof(asymoff_signing_aggregate_msg_round_2_t));
      party->in_aggregate_msg_3 = calloc(num_parties, sizeof(asymoff_signing_aggregate_msg_round_3_t));
    }

    parties[i]->next_index += num_sigs;
  }
  return signing_parties;
}

void asymoff_signing_parties_free(asymoff_signing_data_t **presign_parties) {
  
  free(presign_parties);
}

int asymoff_signing_online_execute_round_1(asymoff_signing_data_t *party) {

  if (party->i == 0) return 1;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_1(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;


  return 0;
}

int asymoff_signing_online_execute_round_2(asymoff_signing_data_t *party) {
  pinfo("Player %ld: Starting Round 2\n", party->i);

  //uint64_t num_parties = party->num_parties;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_2(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;

  return 0;
}


int asymoff_signing_online_execute_round_3(asymoff_signing_data_t *party) {
  pinfo("Player %ld: Starting Round 3\n", party->i);

  //uint64_t num_parties = party->num_parties;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_3(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;

  return 0;
}

int asymoff_signing_online_execute_final(asymoff_signing_data_t *party) {
  pinfo("Player %ld: Starting Final\n", party->i);
  
  if (party->i == 0) return 0;
  
  return 0;
}

void asymoff_signing_export_data(asymoff_party_data_t **parties, asymoff_signing_data_t ** const presign_parties) {
  
  //uint64_t num_parties = parties[0]->num_parties;
  //ec_group_t ec        = parties[0]->ec;

}

int asymoff_signing_online_execute_mock_final (asymoff_signing_data_t **parties) {
  assert(parties[0]->num_parties >= 2);

  uint64_t num_parties  = parties[1]->num_parties;
  uint64_t num_sigs     = parties[1]->num_sigs;
  ec_group_t ec         = parties[1]->ec;

  scalar_t x   = scalar_new();
  scalar_t curr_k     = scalar_new();
  scalar_t curr_k_inv = scalar_new();

  scalar_set_ul(x, 0);
  for (uint64_t i = 1; i < num_parties; ++i) {
    scalar_add(x, x, parties[i]->x, ec_group_order(ec));
  }
  
  for (uint64_t l = 0; l < num_sigs; ++l) {
    
    scalar_set_ul(curr_k, 0);
    for (uint64_t i = 1; i < num_parties; ++i) {
      scalar_add(curr_k, curr_k, parties[i]->nonce[l], ec_group_order(ec));
    }

    scalar_inv(curr_k_inv, curr_k, ec_group_order(ec));

    for (uint64_t i = 1; i < num_parties; ++i) {
      group_operation(parties[i]->R[l], NULL, parties[i]->H[l], curr_k_inv, ec);
    }

    scalar_mul(parties[1]->chi[l], x, curr_k, ec_group_order(ec));
    for (uint64_t i = 2; i < num_parties; ++i) {
      scalar_sample_in_range(parties[i]->chi[l], ec_group_order(ec), 0);
      scalar_sub(parties[1]->chi[l], parties[1]->chi[l], parties[i]->chi[l], ec_group_order(ec));
    }
  }

  scalar_free(x);
  scalar_free(curr_k);
  scalar_free(curr_k_inv);

  return 0;
}

/*****************
 *  Aggregation  *
 *****************/

void asymoff_signing_aggregate_round_1_hash(hash_chunk hash, asymoff_signing_aggregate_msg_round_2_t *msg_2, zkp_aux_info_t * const aux, ec_group_t ec) {

  uint64_t num_sigs = msg_2->pi_eph_anchor->batch_size;

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, aux->info, aux->info_len);
  
  uint8_t *temp_bytes = malloc(GROUP_ELEMENT_BYTES);

  for (uint64_t l = 0; l < num_sigs; ++l) {
    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_eph_anchor->V[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_eph_anchor->W1[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_eph_anchor->W2[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->V1[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->V2[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_chi_anchor->U1, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_chi_anchor->U2, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_chi_anchor->W1, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_chi_anchor->W2, ec, 0);
  SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

  SHA512_Update(&sha_ctx, msg_2->u, sizeof(hash_chunk));
  SHA512_Final(hash, &sha_ctx);

  free(temp_bytes);
}

int asymoff_signing_aggregate_execute_round_1(asymoff_signing_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Starting Aggregate Round 1\n", party->i);

  uint64_t num_sigs    = party->num_sigs;

  zkp_el_gamal_dlog_public_t pi_eph_public;
  pi_eph_public.batch_size = num_sigs;
  pi_eph_public.R  = party->R;
  pi_eph_public.ec  = party->ec;
  pi_eph_public.g  = party->gen;
  pi_eph_public.Y  = party->Y;

  zkp_el_gamal_dlog_anchor(party->pi_eph_anchor, &party->pi_eph_anchor_secret, &pi_eph_public);

  // ZKP Double El Gamal - Sample and Anchor

  for (uint64_t l = 0; l < num_sigs; ++l) {
    scalar_sample_in_range(party->v[l], ec_group_order(party->ec), 0); 

    group_operation(party->V1[l], NULL, party->gen, party->v[l], party->ec);

    group_operation(party->V2[l], NULL, party->gen, party->chi[l], party->ec);
    group_operation(party->V2[l], party->V2[l], party->Y, party->v[l], party->ec);
  }

  zkp_double_el_gamal_public_t pi_chi_public;
  pi_chi_public.batch_size  = num_sigs;
  pi_chi_public.ec = party->ec;
  pi_chi_public.g  = party->gen;
  pi_chi_public.X  = party->online_X;
  pi_chi_public.Y  = party->Y;

  zkp_double_el_gamal_anchor(party->pi_chi_anchor, &party->pi_chi_anchor_secret, &pi_chi_public);

  // pi_chi_public.V1 = party->V1;
  // pi_chi_public.V2 = party->V2;
  // pi_chi_public.B1 = party->B1[party->i];
  // pi_chi_public.B2 = party->B2[party->i];

  // party->pi_chi_anchor_secret.b = party->b;
  // party->pi_chi_anchor_secret.k = party->nonce;
  // party->pi_chi_anchor_secret.v = party->v;

  // zkp_double_el_gamal_proof_t *temp_pi_proof = zkp_double_el_gamal_duplicate(party->pi_chi_anchor);

  // zkp_double_el_gamal_prove(temp_pi_proof, &party->pi_chi_anchor_secret, &pi_chi_public, party->aux);

  // printECPOINT("U1 = ", temp_pi_proof->U1, party->ec, "\n", 1);
  // printECPOINT("U2 = ", temp_pi_proof->U2, party->ec, "\n", 1);
  // printECPOINT("W1 = ", temp_pi_proof->W1, party->ec, "\n", 1);
  // printECPOINT("W2 = ", temp_pi_proof->W2, party->ec, "\n", 1);

  //assert(zkp_double_el_gamal_verify(temp_pi_proof, &pi_chi_public, party->aux) == 1);

  RAND_bytes(party->u, sizeof(hash_chunk));

  asymoff_signing_aggregate_msg_round_2_t msg_2; 
  msg_2.pi_eph_anchor = party->pi_eph_anchor;
  msg_2.pi_chi_anchor = party->pi_chi_anchor;
  msg_2.V1 = party->V1;
  msg_2.V2 = party->V2;
  msg_2.u = &party->u;

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
  asymoff_signing_aggregate_round_1_hash(party->T, &msg_2, party->aux, party->ec);

  return 0;
}

uint64_t asymoff_signing_aggregate_send_msg_1(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_signing_aggregate_msg_round_1_t *in_agg_msg_1 = &receiver->in_aggregate_msg_1[sender->i];

  in_agg_msg_1->T = &sender->T;

  return sizeof(hash_chunk);
}

int asymoff_signing_aggregate_execute_round_2(asymoff_signing_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Starting Aggregate Round 2\n", party->i);

  // For convinience, set in_msg_1 V for self as outgoing V
  party->in_aggregate_msg_1[party->i].T = &party->T;

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  for (uint64_t j = 1; j < party->num_parties; ++j) {
    SHA512_Update(&sha_ctx, *party->in_aggregate_msg_1[j].T, sizeof(hash_chunk));
  }
  SHA512_Final(party->echo_all_T, &sha_ctx);

  return 0;
}

uint64_t asymoff_signing_aggregate_send_msg_2(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_signing_aggregate_msg_round_2_t *in_agg_msg_2 = &receiver->in_aggregate_msg_2[sender->i];

  in_agg_msg_2->pi_eph_anchor  = sender->pi_eph_anchor;
  in_agg_msg_2->pi_chi_anchor  = sender->pi_chi_anchor;
  
  in_agg_msg_2->V1  = sender->V1;
  in_agg_msg_2->V2  = sender->V2;

  in_agg_msg_2->echo_all_T = &sender->echo_all_T;
  in_agg_msg_2->u = &sender->u;

  return 0;
}

int asymoff_signing_aggregate_execute_round_3(asymoff_signing_data_t *party) {
  if (party->i == 0) return 1;

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs = party->num_sigs;
  
  pinfo("Player %ld: Starting Aggregate Round 3\n", party->i);

  hash_chunk computed_T;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_signing_aggregate_msg_round_2_t *in_msg_2 = &party->in_aggregate_msg_2[j];

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));
    asymoff_signing_aggregate_round_1_hash(computed_T, in_msg_2, party->aux, party->ec);

    if (memcmp(computed_T, *party->in_aggregate_msg_1[j].T, sizeof(hash_chunk)) != 0) {
      printf("Bad decommitment of previous round. Received from party %ld\n", j);
      return 1;
    }

    // Verify echo broadcast from others is same
    if (memcmp(party->echo_all_T, in_msg_2->echo_all_T, sizeof(hash_chunk)) != 0) {
      printf("Echo broadcast equality failure. Received from party %ld\n", j);
      return 1;
    }
  }

  // Aggregate Proofs
  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  // ZKP El Gamal Dlog - aggregate and local prove

  zkp_el_gamal_dlog_proof_t  **pi_eph_anchors = calloc(num_parties-1, sizeof(zkp_el_gamal_dlog_proof_t*));
  
  // For convinece
  party->in_aggregate_msg_2[party->i].pi_eph_anchor = party->pi_eph_anchor;

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_eph_anchors[j-1] = party->in_aggregate_msg_2[j].pi_eph_anchor;
  }

  party->pi_eph_agg_public.batch_size = num_sigs;
  party->pi_eph_agg_public.ec = party->ec;
  party->pi_eph_agg_public.g  = party->gen;
  party->pi_eph_agg_public.R  = party->R;
  party->pi_eph_agg_public.Y  = party->Y;
  party->pi_eph_agg_public.H  = party->H;
  party->pi_eph_agg_public.B1 = party->joint_B1;
  party->pi_eph_agg_public.B2 = party->joint_B2;

  party->pi_eph_anchor_secret.b = party->b;
  party->pi_eph_anchor_secret.k = party->nonce;
  
  zkp_el_gamal_dlog_aggregate_anchors(party->pi_eph_local_agg_proof, pi_eph_anchors, num_parties-1);
  zkp_el_gamal_dlog_prove(party->pi_eph_local_agg_proof, &party->pi_eph_anchor_secret, &party->pi_eph_agg_public, party->aux, 1);
  
  // ZKP Double El Gamal - Prove (and compute joint V1/2)

  zkp_double_el_gamal_proof_t  **pi_chi_anchors = calloc(num_parties-1, sizeof(zkp_double_el_gamal_proof_t*));
  
  // For convinece
  party->in_aggregate_msg_2[party->i].pi_chi_anchor = party->pi_chi_anchor;
  party->in_aggregate_msg_2[party->i].V1 = party->V1;
  party->in_aggregate_msg_2[party->i].V2 = party->V2;

  for (uint64_t l = 0; l < party->num_sigs; ++l) {

    group_operation(party->joint_V1[l], NULL, NULL, NULL, party->ec);
    group_operation(party->joint_V2[l], NULL, NULL, NULL, party->ec);

    for (uint64_t j = 1; j < party->num_parties; ++j) {
      group_operation(party->joint_V1[l], party->joint_V1[l], party->in_aggregate_msg_2[j].V1[l], NULL, party->ec);
      group_operation(party->joint_V2[l], party->joint_V2[l], party->in_aggregate_msg_2[j].V2[l], NULL, party->ec);
    }
  }

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_chi_anchors[j-1] = party->in_aggregate_msg_2[j].pi_chi_anchor;
  }

  party->pi_chi_agg_public.batch_size = num_sigs;
  party->pi_chi_agg_public.ec = party->ec;
  party->pi_chi_agg_public.g  = party->gen;
  party->pi_chi_agg_public.X  = party->online_X;
  party->pi_chi_agg_public.Y  = party->Y;
  party->pi_chi_agg_public.B1 = party->joint_B1;
  party->pi_chi_agg_public.B2 = party->joint_B2;
  party->pi_chi_agg_public.V1 = party->joint_V1;
  party->pi_chi_agg_public.V2 = party->joint_V2;
  
  party->pi_chi_anchor_secret.k = party->nonce;
  party->pi_chi_anchor_secret.b = party->b;
  party->pi_chi_anchor_secret.v = party->v;
  
  zkp_double_el_gamal_aggregate_anchors(party->pi_chi_local_agg_proof, pi_chi_anchors, num_parties-1);
  zkp_double_el_gamal_prove(party->pi_chi_local_agg_proof, &party->pi_chi_anchor_secret, &party->pi_chi_agg_public, party->aux);
  
  return 0;
}

uint64_t asymoff_signing_aggregate_send_msg_3(asymoff_signing_data_t *sender, asymoff_signing_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_signing_aggregate_msg_round_3_t *in_agg_msg_3 = &receiver->in_aggregate_msg_3[sender->i];

  in_agg_msg_3->pi_eph_local_proof = sender->pi_eph_local_agg_proof;
  in_agg_msg_3->pi_chi_local_proof = sender->pi_chi_local_agg_proof;

  return zkp_el_gamal_dlog_proof_bytelen(sender->num_sigs, 1) + zkp_double_el_gamal_proof_bytelen();
}

int asymoff_signing_aggregate_execute_final (asymoff_signing_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Starting Aggregate Final Round\n", party->i);

  uint64_t num_parties = party->num_parties;

  // Aggregate local proofs to a single proof and verify it

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  // For convinece
  party->in_aggregate_msg_3[party->i].pi_eph_local_proof = party->pi_eph_local_agg_proof;
  party->in_aggregate_msg_3[party->i].pi_chi_local_proof = party->pi_chi_local_agg_proof;

  zkp_el_gamal_dlog_proof_t **pi_eph_local_proofs = calloc(num_parties-1, sizeof(zkp_el_gamal_dlog_proof_t*));
  zkp_double_el_gamal_proof_t **pi_chi_local_proofs = calloc(num_parties-1, sizeof(zkp_double_el_gamal_proof_t*));

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_eph_local_proofs[j-1] = party->in_aggregate_msg_3[j].pi_eph_local_proof;
    pi_chi_local_proofs[j-1] = party->in_aggregate_msg_3[j].pi_chi_local_proof;
  }
  
  zkp_el_gamal_dlog_proof_t *pi_eph_agg_proof = zkp_el_gamal_dlog_duplicate(party->pi_eph_local_agg_proof);
  zkp_el_gamal_dlog_aggregate_local_proofs(pi_eph_agg_proof, pi_eph_local_proofs, num_parties-1);
  
  if (zkp_el_gamal_dlog_verify(pi_eph_agg_proof, &party->pi_eph_agg_public, party->aux, 1) != 1) {
    printf("Aggregated ZKP Ephemeral El Gamal DLog verification failed.\n");
    return 1;
  }

  zkp_double_el_gamal_proof_t *pi_chi_agg_proof = zkp_double_el_gamal_duplicate(party->pi_chi_local_agg_proof);
  zkp_double_el_gamal_aggregate_local_proofs(pi_chi_agg_proof, pi_chi_local_proofs, num_parties-1);
  
  if (zkp_double_el_gamal_verify(pi_chi_agg_proof, &party->pi_chi_agg_public, party->aux) != 1) {
    printf("Aggregated Chi ZKP Double El Gamal verification failed.\n");
    return 1;
  }

  free(pi_eph_local_proofs);
  free(pi_chi_local_proofs);
  zkp_el_gamal_dlog_free(pi_eph_agg_proof);

  return 0;
}