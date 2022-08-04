#include "asymoff_signing_aggregate.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

asymoff_sign_agg_data_t **asymoff_signing_aggregate_parties_new(asymoff_party_data_t ** parties, scalar_t *msgs)  {
  
  uint64_t num_parties = parties[0]->num_parties;
  uint64_t num_sigs    = parties[0]->num_sigs;
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  assert(num_parties >= 2);
  
  asymoff_sign_agg_data_t **signing_parties = calloc(num_parties, sizeof(asymoff_sign_agg_data_t *));

  for (uint64_t i = 0; i < num_parties; ++i) {
    
    uint64_t curr_index = parties[i]->curr_index;

    if (parties[i]->next_index < curr_index + num_sigs) {
      printf("Not enough presigning buffer - did you run cmp with enough sigs before aggregation?");
      return NULL;
    }

    // Assume will use all, to avoid double use
    parties[i]->curr_index = parties[i]->next_index;
    
    ec_group_t ec = parties[i]->ec;

    signing_parties[i] = malloc(sizeof(asymoff_sign_agg_data_t));

    asymoff_sign_agg_data_t *party = signing_parties[i];

    party->i = i;
    party->num_parties = num_parties;
    party->num_sigs = num_sigs;

    party->ec = ec;
    party->Y = parties[i]->Y;
    party->X = parties[i]->X;
    party->x = parties[i]->x;

    party->online_X = group_elem_new(ec);
    group_operation(party->online_X, NULL , NULL,NULL, NULL, ec, bn_ctx);
    for (uint64_t i = 1; i < num_parties; ++i) group_operation(party->online_X, party->online_X, NULL, party->X[i], NULL, ec, bn_ctx);
    
    party->paillier_pub = parties[i]->paillier_pub;
    party->rped_pub = parties[i]->rped_pub;

    uint64_t aux_pos = 0;
    party->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->sid, sizeof(hash_chunk));
    zkp_aux_info_update_move(party->aux, &aux_pos, &party->i, sizeof(uint64_t));
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->srid, sizeof(hash_chunk));
    assert(party->aux->info_len == aux_pos);

    party->R      = &parties[i]->R[curr_index];  
    party->chi    = &parties[i]->chi[curr_index];
    party->nonce  = &parties[i]->nonce[curr_index];
    party->b      = &parties[i]->b[curr_index];
    party->H      = &parties[i]->H[curr_index];

    party->joint_B1 = &parties[i]->joint_B1[curr_index];
    party->joint_B2 = &parties[i]->joint_B2[curr_index];

    party->joint_V1 = gr_el_array_new(num_sigs, ec);
    party->joint_V2 = gr_el_array_new(num_sigs, ec);
  
    party->W_0 = parties[i]->W_0;

    party->msgs = scalar_array_new(num_sigs);
    scalar_array_copy(party->msgs, msgs, num_sigs);

    if (i == 0) {

      party->in_aggregate_msg_offline = malloc(sizeof(asymoff_sign_agg_msg_offline_t));

      party->signature_sigma = scalar_array_new(num_sigs);
      party->paillier_offline_priv = parties[i]->paillier_priv;

    } else {

      party->B1 = calloc(num_parties, sizeof(gr_elem_t *));
      party->B2 = calloc(num_parties, sizeof(gr_elem_t *));

      for (uint64_t j = 1; j < num_parties; ++j) {
        party->B1[j] = &parties[i]->B1[j][curr_index];
        party->B2[j] = &parties[i]->B2[j][curr_index];
      }

      party->V1 = gr_el_array_new(num_sigs, ec);
      party->V2 = gr_el_array_new(num_sigs, ec);

      party->v = scalar_array_new(num_sigs);

      party->pi_eph_anchor          = zkp_el_gamal_dlog_new(num_sigs, ec);
      party->pi_eph_local_agg_proof = zkp_el_gamal_dlog_new(num_sigs, ec);
      party->pi_eph_agg_proof       = zkp_el_gamal_dlog_new(num_sigs, ec);
      
      // party->pi_eph_agg_public.B1 = new_gr_el_array(num_sigs, party->ec);
      // party->pi_eph_agg_public.B2 = new_gr_el_array(num_sigs, party->ec);

      party->pi_eph_anchor_secret.lambda = scalar_array_new(num_sigs);
      party->pi_eph_anchor_secret.rho    = scalar_array_new(num_sigs);

      // Chi proof related 

      party->pi_chi_anchor          = zkp_double_el_gamal_new(ec);
      party->pi_chi_local_agg_proof = zkp_double_el_gamal_new(ec);
      party->pi_chi_agg_proof       = zkp_double_el_gamal_new(ec);
      
      // party->pi_chi_agg_public.B1 = new_gr_el_array(num_sigs, party->ec);
      // party->pi_chi_agg_public.B2 = new_gr_el_array(num_sigs, party->ec);
      // party->pi_chi_agg_public.V1 = new_gr_el_array(num_sigs, party->ec);
      // party->pi_chi_agg_public.V2 = new_gr_el_array(num_sigs, party->ec);

      party->pi_chi_anchor_secret.alpha = scalar_new();
      party->pi_chi_anchor_secret.beta  = scalar_new();
      party->pi_chi_anchor_secret.gamma = scalar_new();

      // Well formed signature related init
      
      party->pi_sig_anchor          = zkp_well_formed_signature_new(num_sigs, PACKING_SIZE, ec);
      party->pi_sig_local_agg_proof = zkp_well_formed_signature_new(num_sigs, PACKING_SIZE, ec);
      party->pi_sig_agg_proof       = zkp_well_formed_signature_new(num_sigs, PACKING_SIZE, ec);

      party->pi_sig_agg_public.packed_Z = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_agg_public.packed_S = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_agg_public.L1 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_agg_public.L2 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_agg_public.U1 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_agg_public.U2 = gr_el_array_new(num_sigs, ec);

      party->pi_sig_local_public.packed_S = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_local_public.packed_Z = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_local_public.L1 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_local_public.L2 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_local_public.U1 = gr_el_array_new(num_sigs, ec);
      party->pi_sig_local_public.U2 = gr_el_array_new(num_sigs, ec);

      party->pi_sig_anchor_secret.r  = scalar_new();
      party->pi_sig_anchor_secret.nu = scalar_new();
      party->pi_sig_anchor_secret.rho     = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_anchor_secret.lambda  = scalar_array_new(num_sigs/PACKING_SIZE);
      party->pi_sig_anchor_secret.mu      = scalar_array_new(num_sigs);
      party->pi_sig_anchor_secret.xi      = scalar_array_new(num_sigs);
      party->pi_sig_anchor_secret.gamma_LB = scalar_array_new(num_sigs);
      party->pi_sig_anchor_secret.gamma_UA = scalar_array_new(num_sigs);
      
      party->pi_sig_anchor_secret.packing_size = PACKING_SIZE;
      party->pi_sig_anchor_secret.alpha    = scalar_array_new(PACKING_SIZE);
      party->pi_sig_anchor_secret.beta     = scalar_array_new(PACKING_SIZE);
      party->pi_sig_anchor_secret.delta_LB = scalar_array_new(PACKING_SIZE);
      party->pi_sig_anchor_secret.delta_UA = scalar_array_new(PACKING_SIZE);

      party->in_aggregate_msg_1 = calloc(num_parties, sizeof(asymoff_sign_agg_msg_round_1_t));
      party->in_aggregate_msg_2 = calloc(num_parties, sizeof(asymoff_sign_agg_msg_round_2_t));
      party->in_aggregate_msg_3 = calloc(num_parties, sizeof(asymoff_sign_agg_msg_round_3_t));
    }
  }

  BN_CTX_free(bn_ctx);

  return signing_parties;
}

void asymoff_signing_aggregate_parties_free(asymoff_sign_agg_data_t **signing_parties) {

  uint64_t num_parties = signing_parties[0]->num_parties;
  uint64_t num_sigs    = signing_parties[0]->num_sigs;
  
  
  for (uint64_t i = 0; i < num_parties; ++i) {
    
    asymoff_sign_agg_data_t *party = signing_parties[i];

    zkp_aux_info_free(party->aux);
    
    group_elem_free(party->online_X);

    gr_el_array_free(party->joint_V1, num_sigs);
    gr_el_array_free(party->joint_V2, num_sigs);
    
    scalar_array_free(party->msgs, num_sigs);

    if (i == 0) {

      free(party->in_aggregate_msg_offline);

      scalar_array_free(party->signature_sigma, num_sigs);

    } else {

      free(party->B1);
      free(party->B2);

      gr_el_array_free(party->V1, num_sigs);
      gr_el_array_free(party->V2, num_sigs);

      scalar_array_free(party->v, num_sigs);

      zkp_el_gamal_dlog_free(party->pi_eph_anchor         );
      zkp_el_gamal_dlog_free(party->pi_eph_local_agg_proof);
      zkp_el_gamal_dlog_free(party->pi_eph_agg_proof      );

      scalar_array_free(party->pi_eph_anchor_secret.lambda, num_sigs);
      scalar_array_free(party->pi_eph_anchor_secret.rho   , num_sigs);

      // Chi proof related 

      zkp_double_el_gamal_free(party->pi_chi_anchor         );
      zkp_double_el_gamal_free(party->pi_chi_local_agg_proof);
      zkp_double_el_gamal_free(party->pi_chi_agg_proof      );
      

      scalar_free(party->pi_chi_anchor_secret.alpha);
      scalar_free(party->pi_chi_anchor_secret.beta );
      scalar_free(party->pi_chi_anchor_secret.gamma);

      // Well formed signature related init
      
      zkp_well_formed_signature_free(party->pi_sig_anchor         );
      zkp_well_formed_signature_free(party->pi_sig_local_agg_proof);
      zkp_well_formed_signature_free(party->pi_sig_agg_proof      );

      scalar_array_free(party->pi_sig_agg_public.packed_Z, num_sigs/PACKING_SIZE);
      scalar_array_free(party->pi_sig_agg_public.packed_S, num_sigs/PACKING_SIZE);
      gr_el_array_free(party->pi_sig_agg_public.L1, num_sigs);
      gr_el_array_free(party->pi_sig_agg_public.L2, num_sigs);
      gr_el_array_free(party->pi_sig_agg_public.U1, num_sigs);
      gr_el_array_free(party->pi_sig_agg_public.U2, num_sigs);

      scalar_array_free(party->pi_sig_local_public.packed_S, num_sigs/PACKING_SIZE);
      scalar_array_free(party->pi_sig_local_public.packed_Z, num_sigs/PACKING_SIZE);
      gr_el_array_free(party->pi_sig_local_public.L1, num_sigs);
      gr_el_array_free(party->pi_sig_local_public.L2, num_sigs);
      gr_el_array_free(party->pi_sig_local_public.U1, num_sigs);
      gr_el_array_free(party->pi_sig_local_public.U2, num_sigs);

      scalar_free(party->pi_sig_anchor_secret.r );
      scalar_free(party->pi_sig_anchor_secret.nu);
      scalar_array_free(party->pi_sig_anchor_secret.rho     , num_sigs/PACKING_SIZE);
      scalar_array_free(party->pi_sig_anchor_secret.lambda  , num_sigs/PACKING_SIZE);
      scalar_array_free(party->pi_sig_anchor_secret.mu      , num_sigs);
      scalar_array_free(party->pi_sig_anchor_secret.xi      , num_sigs);
      scalar_array_free(party->pi_sig_anchor_secret.gamma_LB, num_sigs);
      scalar_array_free(party->pi_sig_anchor_secret.gamma_UA, num_sigs);
      
      scalar_array_free(party->pi_sig_anchor_secret.alpha   , PACKING_SIZE);
      scalar_array_free(party->pi_sig_anchor_secret.beta    , PACKING_SIZE);
      scalar_array_free(party->pi_sig_anchor_secret.delta_LB, PACKING_SIZE);
      scalar_array_free(party->pi_sig_anchor_secret.delta_UA, PACKING_SIZE);

      free(party->in_aggregate_msg_1);
      free(party->in_aggregate_msg_2);
      free(party->in_aggregate_msg_3);
    }

    free(signing_parties[i]);
  }

  free(signing_parties);
}

void asymoff_signing_aggregate_round_1_hash(hash_chunk hash, asymoff_sign_agg_msg_round_2_t *msg_2, zkp_aux_info_t * const aux, ec_group_t ec) {

  uint64_t num_sigs = msg_2->pi_eph_anchor->batch_size;

  SHA512_CTX sha_ctx;
  SHA512_Init(&sha_ctx);
  SHA512_Update(&sha_ctx, aux->info, aux->info_len);
  
  uint8_t *temp_bytes = malloc(2*PAILLIER_MODULUS_BYTES);

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

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->L1[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->L2[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->U1[l], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->U2[l], ec, 0);
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

  for (uint64_t l = 0; l < num_sigs/PACKING_SIZE; ++l) {
    scalar_to_bytes(&temp_bytes, 2*PAILLIER_MODULUS_BYTES, msg_2->packed_Z[l], 0);
    SHA512_Update(&sha_ctx, temp_bytes, 2*PAILLIER_MODULUS_BYTES);

    scalar_to_bytes(&temp_bytes, RING_PED_MODULUS_BYTES, msg_2->packed_S[l], 0);
    SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);

  }

  scalar_to_bytes(&temp_bytes, 2*PAILLIER_MODULUS_BYTES, msg_2->pi_sig_anchor->V, 0);
  SHA512_Update(&sha_ctx, temp_bytes, 2*PAILLIER_MODULUS_BYTES);

  scalar_to_bytes(&temp_bytes, RING_PED_MODULUS_BYTES, msg_2->pi_sig_anchor->T, 0);
  SHA512_Update(&sha_ctx, temp_bytes, RING_PED_MODULUS_BYTES);

  for (uint64_t p = 0; p < PACKING_SIZE; ++p) {

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_sig_anchor->A1[p], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_sig_anchor->A2[p], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_sig_anchor->B1[p], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);

    group_elem_to_bytes(&temp_bytes, GROUP_ELEMENT_BYTES, msg_2->pi_sig_anchor->B2[p], ec, 0);
    SHA512_Update(&sha_ctx, temp_bytes, GROUP_ELEMENT_BYTES);
  }

  SHA512_Update(&sha_ctx, msg_2->u, sizeof(hash_chunk));
  SHA512_Final(hash, &sha_ctx);

  free(temp_bytes);
}

int asymoff_signing_aggregate_execute_round_1(asymoff_sign_agg_data_t *party) {
  if (party->i == 0) return 1;

  ec_group_t ec = party->ec;
  scalar_t ec_order = ec_group_order(party->ec);

  pinfo("Player %ld: Executing Aggregate Round 1\n", party->i);
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t num_sigs    = party->num_sigs;

  zkp_el_gamal_dlog_public_t pi_eph_public;
  pi_eph_public.batch_size = num_sigs;
  pi_eph_public.R  = party->R;
  pi_eph_public.ec = party->ec;
  pi_eph_public.Y  = party->Y;

  zkp_el_gamal_dlog_anchor(party->pi_eph_anchor, &party->pi_eph_anchor_secret, &pi_eph_public);

  // ZKP Double El Gamal
    
  // Sample and compute

  for (uint64_t l = 0; l < num_sigs; ++l) {

    scalar_sample_in_range(party->v[l], ec_order, 0, bn_ctx); 

    group_operation(party->V1[l], NULL, party->v[l], NULL, NULL, ec, bn_ctx);
    group_operation(party->V2[l], NULL, party->chi[l], party->Y, party->v[l], ec, bn_ctx);
  }

  // Anchor

  zkp_double_el_gamal_public_t pi_chi_public;
  pi_chi_public.batch_size  = num_sigs;
  pi_chi_public.ec = party->ec;
  pi_chi_public.X  = party->online_X;
  pi_chi_public.Y  = party->Y;
  
  zkp_double_el_gamal_anchor(party->pi_chi_anchor, &party->pi_chi_anchor_secret, &pi_chi_public);

  // --- ZKP Well Formed Signature ---

  // Sample and compute

  scalar_t r      = scalar_new();
  scalar_t eta    = scalar_new();
  scalar_t temp   = scalar_new();
  scalar_t packed = scalar_new();
  scalar_t rped_s_exps[2*PACKING_SIZE];

  for (uint64_t l = 0; l < num_sigs; ++l) {

    scalar_set_power_of_2(temp, 256+64); // TODO: Fix all EPS and ELL
    scalar_sample_in_range(eta, temp, 0, bn_ctx);
    scalar_make_signed(eta, eta);

    group_elem_get_x(r, party->R[l], party->ec, ec_order);
    
    BN_mod_mul(temp, r, party->chi[l], ec_order, bn_ctx);
    BN_mod_mul(party->pi_sig_anchor_secret.mu[l], party->msgs[l], party->nonce[l], ec_order, bn_ctx);
    BN_mod_add(party->pi_sig_anchor_secret.mu[l], party->pi_sig_anchor_secret.mu[l], temp, ec_order, bn_ctx);

    BN_mul(temp, ec_order, eta, bn_ctx);
    BN_add(party->pi_sig_anchor_secret.mu[l], party->pi_sig_anchor_secret.mu[l], temp);
    
    BN_mod_mul(party->pi_sig_anchor_secret.xi[l], r, party->nonce[l], ec_order, bn_ctx);

    BN_mod_mul(party->pi_sig_anchor_secret.gamma_LB[l], r, party->b[l], ec_order, bn_ctx);
    
    BN_mod_mul(temp, r, party->v[l], ec_order, bn_ctx);
    BN_mod_mul(party->pi_sig_anchor_secret.gamma_UA[l], party->msgs[l], party->b[l], ec_order, bn_ctx);
    BN_mod_add(party->pi_sig_anchor_secret.gamma_UA[l], party->pi_sig_anchor_secret.gamma_UA[l], temp, ec_order, bn_ctx);

    group_operation(party->pi_sig_local_public.L1[l], NULL, NULL, party->B1[party->i][l], r, ec, bn_ctx); 

    group_operation(party->pi_sig_local_public.L2[l], NULL, NULL, party->B2[party->i][l], r, ec, bn_ctx); 

    group_operation(party->pi_sig_local_public.U1[l], NULL, NULL, party->V1[l], r, ec, bn_ctx); 
    group_operation(party->pi_sig_local_public.U1[l], party->pi_sig_local_public.U1[l], NULL, party->B1[party->i][l], party->msgs[l], ec, bn_ctx); 
  
    group_operation(party->pi_sig_local_public.U2[l], NULL, NULL, party->V2[l], r, ec, bn_ctx);   
    group_operation(party->pi_sig_local_public.U2[l], party->pi_sig_local_public.U2[l], NULL, party->B2[party->i][l], party->msgs[l], ec, bn_ctx); 
  }

  for (uint64_t l = 0; l < num_sigs/PACKING_SIZE; ++l) {

    BN_lshift(temp, party->rped_pub[0]->N, 256); // TODO: replaace 256
    scalar_sample_in_range(party->pi_sig_anchor_secret.lambda[l], temp, 0, bn_ctx);
    
    for (uint64_t p = 0; p < PACKING_SIZE; ++p) {
      rped_s_exps[p]                = party->pi_sig_anchor_secret.mu[PACKING_SIZE*l + p];
      rped_s_exps[PACKING_SIZE + p] = party->pi_sig_anchor_secret.xi[PACKING_SIZE*l + p];
    }
    ring_pedersen_commit(party->pi_sig_local_public.packed_S[l], rped_s_exps, 2*PACKING_SIZE, party->pi_sig_anchor_secret.lambda[l], party->rped_pub[0]);
  
    pack_plaintexts(packed, &party->pi_sig_anchor_secret.mu[PACKING_SIZE*l], PACKING_SIZE, party->paillier_pub[0]->N, 1);

    paillier_encryption_sample(party->pi_sig_anchor_secret.rho[l], party->paillier_pub[0]);
    paillier_encryption_encrypt(party->pi_sig_local_public.packed_Z[l], packed, party->pi_sig_anchor_secret.rho[l], party->paillier_pub[0]);

    pack_plaintexts(packed, &party->pi_sig_anchor_secret.xi[PACKING_SIZE*l], PACKING_SIZE, party->paillier_pub[0]->N, 1);
    paillier_encryption_homomorphic(party->pi_sig_local_public.packed_Z[l], party->W_0, packed, party->pi_sig_local_public.packed_Z[l], party->paillier_pub[0]);
  }

  // Anchor

  zkp_well_formed_signature_public_t pi_sig_public;
  pi_sig_public.paillier_pub = party->paillier_pub[0];
  pi_sig_public.rped_pub     = party->rped_pub[0];
  pi_sig_public.batch_size   = num_sigs;
  pi_sig_public.packing_size = PACKING_SIZE;
  pi_sig_public.ec = party->ec;
  pi_sig_public.W  = party->W_0;
  pi_sig_public.Y  = party->Y;
  
  zkp_well_formed_signature_anchor(party->pi_sig_anchor, &party->pi_sig_anchor_secret, &pi_sig_public);

  scalar_free(r);
  scalar_free(eta);
  scalar_free(temp);
  scalar_free(packed);
  BN_CTX_free(bn_ctx);
  
  // Commit to future msg

  RAND_bytes(party->u, sizeof(hash_chunk));

  asymoff_sign_agg_msg_round_2_t msg_2; 
  msg_2.pi_eph_anchor = party->pi_eph_anchor;
  msg_2.pi_chi_anchor = party->pi_chi_anchor;
  msg_2.pi_sig_anchor = party->pi_sig_anchor;

  msg_2.V1 = party->V1;
  msg_2.V2 = party->V2;

  msg_2.packed_Z = party->pi_sig_local_public.packed_Z;
  msg_2.packed_S = party->pi_sig_local_public.packed_S;

  msg_2.L1 = party->pi_sig_local_public.L1;
  msg_2.L2 = party->pi_sig_local_public.L2;
  msg_2.U1 = party->pi_sig_local_public.U1;
  msg_2.U2 = party->pi_sig_local_public.U2;

  msg_2.u = &party->u;

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
  asymoff_signing_aggregate_round_1_hash(party->T, &msg_2, party->aux, party->ec);

  return 0;
}

uint64_t asymoff_signing_aggregate_send_msg_1(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_agg_msg_round_1_t *in_agg_msg_1 = &receiver->in_aggregate_msg_1[sender->i];

  in_agg_msg_1->T = &sender->T;

  return sizeof(hash_chunk);
}

int asymoff_signing_aggregate_execute_round_2(asymoff_sign_agg_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Aggregate Round 2\n", party->i);

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

uint64_t asymoff_signing_aggregate_send_msg_2(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_agg_msg_round_2_t *in_agg_msg_2 = &receiver->in_aggregate_msg_2[sender->i];

  in_agg_msg_2->pi_eph_anchor  = sender->pi_eph_anchor;
  in_agg_msg_2->pi_chi_anchor  = sender->pi_chi_anchor;
  in_agg_msg_2->pi_sig_anchor  = sender->pi_sig_anchor;
  
  in_agg_msg_2->V1  = sender->V1;
  in_agg_msg_2->V2  = sender->V2;

  in_agg_msg_2->packed_S = sender->pi_sig_local_public.packed_S;
  in_agg_msg_2->packed_Z = sender->pi_sig_local_public.packed_Z;

  in_agg_msg_2->L1 = sender->pi_sig_local_public.L1;
  in_agg_msg_2->L2 = sender->pi_sig_local_public.L2;
  in_agg_msg_2->U1 = sender->pi_sig_local_public.U1;
  in_agg_msg_2->U2 = sender->pi_sig_local_public.U2;

  in_agg_msg_2->echo_all_T = &sender->echo_all_T;
  in_agg_msg_2->u = &sender->u;

  return zkp_el_gamal_dlog_anchor_bytelen(sender->num_sigs, 0) + zkp_double_el_gamal_anchor_bytelen() + zkp_well_formed_signature_anchor_bytelen(PACKING_SIZE) + sender->num_sigs*6*GROUP_ELEMENT_BYTES + (sender->num_sigs/PACKING_SIZE) *(RING_PED_MODULUS_BYTES + 2*PAILLIER_MODULUS_BYTES) + 2*sizeof(hash_chunk);
}

int asymoff_signing_aggregate_execute_round_3(asymoff_sign_agg_data_t *party) {
  if (party->i == 0) return 1;

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs = party->num_sigs;
  
  pinfo("Player %ld: Executing Aggregate Round 3\n", party->i);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  hash_chunk computed_T;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue;

    asymoff_sign_agg_msg_round_2_t *in_msg_2 = &party->in_aggregate_msg_2[j];

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

  // ----- ZKP El Gamal Dlog -----

  zkp_el_gamal_dlog_proof_t  **pi_eph_anchors = calloc(num_parties-1, sizeof(zkp_el_gamal_dlog_proof_t*));
  
  // For convinience
  party->in_aggregate_msg_2[party->i].pi_eph_anchor = party->pi_eph_anchor;

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_eph_anchors[j-1] = party->in_aggregate_msg_2[j].pi_eph_anchor;
  }

  party->pi_eph_agg_public.batch_size = num_sigs;
  party->pi_eph_agg_public.ec = party->ec;
  party->pi_eph_agg_public.R  = party->R;
  party->pi_eph_agg_public.Y  = party->Y;
  party->pi_eph_agg_public.H  = party->H;
  party->pi_eph_agg_public.B1 = party->joint_B1;
  party->pi_eph_agg_public.B2 = party->joint_B2;

  party->pi_eph_anchor_secret.b = party->b;
  party->pi_eph_anchor_secret.k = party->nonce;
  
  zkp_el_gamal_dlog_aggregate_anchors(party->pi_eph_local_agg_proof, pi_eph_anchors, num_parties-1);
  zkp_el_gamal_dlog_prove(party->pi_eph_local_agg_proof, &party->pi_eph_anchor_secret, &party->pi_eph_agg_public, party->aux, 0);
  
  // ----- ZKP Double El Gamal ------
  
  // Compute joint V1/2

  // For convinience
  party->in_aggregate_msg_2[party->i].pi_chi_anchor = party->pi_chi_anchor;
  party->in_aggregate_msg_2[party->i].V1 = party->V1;
  party->in_aggregate_msg_2[party->i].V2 = party->V2;


  for (uint64_t l = 0; l < party->num_sigs; ++l) {

    group_operation(party->joint_V1[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);
    group_operation(party->joint_V2[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);

    for (uint64_t j = 1; j < party->num_parties; ++j) {
      group_operation(party->joint_V1[l], party->joint_V1[l], NULL, party->in_aggregate_msg_2[j].V1[l], NULL, party->ec, bn_ctx);
      group_operation(party->joint_V2[l], party->joint_V2[l], NULL, party->in_aggregate_msg_2[j].V2[l], NULL, party->ec, bn_ctx);
    }
  }

  // Local prove against joint values

  party->pi_chi_agg_public.batch_size = num_sigs;
  party->pi_chi_agg_public.ec = party->ec;
  party->pi_chi_agg_public.X  = party->online_X;
  party->pi_chi_agg_public.Y  = party->Y;
  party->pi_chi_agg_public.B1 = party->joint_B1;
  party->pi_chi_agg_public.B2 = party->joint_B2;
  party->pi_chi_agg_public.V1 = party->joint_V1;
  party->pi_chi_agg_public.V2 = party->joint_V2;
  
  // Partial anchor was already generated before

  party->pi_chi_anchor_secret.k = party->nonce;
  party->pi_chi_anchor_secret.b = party->b;
  party->pi_chi_anchor_secret.v = party->v;

  zkp_double_el_gamal_proof_t  **pi_chi_anchors = calloc(num_parties-1, sizeof(zkp_double_el_gamal_proof_t*));

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_chi_anchors[j-1] = party->in_aggregate_msg_2[j].pi_chi_anchor;
  }
  
  zkp_double_el_gamal_aggregate_anchors(party->pi_chi_local_agg_proof, pi_chi_anchors, num_parties-1);
  zkp_double_el_gamal_prove(party->pi_chi_local_agg_proof, &party->pi_chi_anchor_secret, &party->pi_chi_agg_public, party->aux);
  
  // ----- ZKP Well Formed Signature -----

  // Compute aggregate 

  // For convinience

  party->in_aggregate_msg_2[party->i].pi_sig_anchor = party->pi_sig_anchor;
  party->in_aggregate_msg_2[party->i].packed_Z = party->pi_sig_local_public.packed_Z;
  party->in_aggregate_msg_2[party->i].packed_S = party->pi_sig_local_public.packed_S;
  party->in_aggregate_msg_2[party->i].L1 = party->pi_sig_local_public.L1;
  party->in_aggregate_msg_2[party->i].L2 = party->pi_sig_local_public.L2;
  party->in_aggregate_msg_2[party->i].U1 = party->pi_sig_local_public.U1;
  party->in_aggregate_msg_2[party->i].U2 = party->pi_sig_local_public.U2;

  for (uint64_t l = 0; l < num_sigs/PACKING_SIZE; ++l) {

    scalar_set_ul(party->pi_sig_agg_public.packed_Z[l], 1);
    scalar_set_ul(party->pi_sig_agg_public.packed_S[l], 1);

     for (uint64_t j = 1; j < num_parties; ++j) {

      paillier_encryption_homomorphic(party->pi_sig_agg_public.packed_Z[l], party->pi_sig_agg_public.packed_Z[l], NULL, party->in_aggregate_msg_2[j].packed_Z[l], party->paillier_pub[0]);
      scalar_mul(party->pi_sig_agg_public.packed_S[l], party->pi_sig_agg_public.packed_S[l], party->in_aggregate_msg_2[j].packed_S[l], party->rped_pub[0]->N, bn_ctx);
     }
  }

  for (uint64_t l = 0; l < num_sigs; ++l) {

    group_operation(party->pi_sig_agg_public.L1[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);
    group_operation(party->pi_sig_agg_public.L2[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);
    group_operation(party->pi_sig_agg_public.U1[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);
    group_operation(party->pi_sig_agg_public.U2[l], NULL, NULL, NULL, NULL, party->ec, bn_ctx);
    
    for (uint64_t j = 1; j < num_parties; ++j) {

      group_operation(party->pi_sig_agg_public.L1[l], party->pi_sig_agg_public.L1[l], NULL, party->in_aggregate_msg_2[j].L1[l], NULL, party->ec, bn_ctx);
      group_operation(party->pi_sig_agg_public.L2[l], party->pi_sig_agg_public.L2[l], NULL, party->in_aggregate_msg_2[j].L2[l], NULL, party->ec, bn_ctx);
      group_operation(party->pi_sig_agg_public.U1[l], party->pi_sig_agg_public.U1[l], NULL, party->in_aggregate_msg_2[j].U1[l], NULL, party->ec, bn_ctx);
      group_operation(party->pi_sig_agg_public.U2[l], party->pi_sig_agg_public.U2[l], NULL, party->in_aggregate_msg_2[j].U2[l], NULL, party->ec, bn_ctx);
    }
  }

  // Local prove against joint values
  
  party->pi_sig_agg_public.batch_size = num_sigs;
  party->pi_sig_agg_public.packing_size = PACKING_SIZE;
  party->pi_sig_agg_public.paillier_pub = party->paillier_pub[0];
  party->pi_sig_agg_public.rped_pub = party->rped_pub[0];
  party->pi_sig_agg_public.ec = party->ec;
  party->pi_sig_agg_public.Y  = party->Y;
  party->pi_sig_agg_public.W  = party->W_0;

  zkp_well_formed_signature_proof_t **pi_sig_anchors = calloc(num_parties-1, sizeof(zkp_well_formed_signature_proof_t*));

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_sig_anchors[j-1] = party->in_aggregate_msg_2[j].pi_sig_anchor;
  }
  
  zkp_well_formed_signature_aggregate_anchors(party->pi_sig_local_agg_proof, pi_sig_anchors, num_parties-1, party->paillier_pub[0], party->rped_pub[0]);
  zkp_well_formed_signature_prove(party->pi_sig_local_agg_proof, &party->pi_sig_anchor_secret, &party->pi_sig_agg_public, party->aux);
  
  free(pi_eph_anchors);
  free(pi_chi_anchors);
  free(pi_sig_anchors);
  BN_CTX_free(bn_ctx);

  return 0;
}

uint64_t asymoff_signing_aggregate_send_msg_3(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_agg_msg_round_3_t *in_agg_msg_3 = &receiver->in_aggregate_msg_3[sender->i];

  in_agg_msg_3->pi_eph_local_agg_proof = sender->pi_eph_local_agg_proof;
  in_agg_msg_3->pi_chi_local_agg_proof = sender->pi_chi_local_agg_proof;
  in_agg_msg_3->pi_sig_local_agg_proof = sender->pi_sig_local_agg_proof;

  return zkp_el_gamal_dlog_proof_bytelen(sender->num_sigs, 0) + zkp_double_el_gamal_proof_bytelen() + zkp_well_formed_signature_proof_bytelen(PACKING_SIZE);
}

int asymoff_signing_aggregate_execute_final (asymoff_sign_agg_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Aggregate Finalization\n", party->i);

  uint64_t num_parties = party->num_parties;

  // Helper value for ZKP well formed sig: #bits + 1 of num_parties;
  int bitlen_plus_1_num_parties = 1;
  uint64_t target_next = 1;
  while (target_next <= num_parties) {
    target_next *= 2;
    ++bitlen_plus_1_num_parties;
  }

  // Aggregate local proofs to a single proof and verify it

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &num_parties, sizeof(uint64_t));

  // For convinience
  party->in_aggregate_msg_3[party->i].pi_eph_local_agg_proof = party->pi_eph_local_agg_proof;
  party->in_aggregate_msg_3[party->i].pi_chi_local_agg_proof = party->pi_chi_local_agg_proof;
  party->in_aggregate_msg_3[party->i].pi_sig_local_agg_proof = party->pi_sig_local_agg_proof;

  zkp_el_gamal_dlog_proof_t **pi_eph_local_proofs = calloc(num_parties-1, sizeof(zkp_el_gamal_dlog_proof_t*));
  zkp_double_el_gamal_proof_t **pi_chi_local_proofs = calloc(num_parties-1, sizeof(zkp_double_el_gamal_proof_t*));
  zkp_well_formed_signature_proof_t **pi_sig_local_proofs = calloc(num_parties-1, sizeof(zkp_well_formed_signature_proof_t*));

  for (uint64_t j = 1; j < party->num_parties; ++j) {
    pi_eph_local_proofs[j-1] = party->in_aggregate_msg_3[j].pi_eph_local_agg_proof;
    pi_chi_local_proofs[j-1] = party->in_aggregate_msg_3[j].pi_chi_local_agg_proof;
    pi_sig_local_proofs[j-1] = party->in_aggregate_msg_3[j].pi_sig_local_agg_proof;
  }
  
  zkp_el_gamal_dlog_copy(party->pi_eph_agg_proof, party->pi_eph_local_agg_proof);
  zkp_el_gamal_dlog_aggregate_local_proofs(party->pi_eph_agg_proof, pi_eph_local_proofs, num_parties-1);
  
  if (zkp_el_gamal_dlog_verify(party->pi_eph_agg_proof, &party->pi_eph_agg_public, party->aux, 0) != 1) {
    printf("Aggregated ZKP Ephemeral El Gamal DLog verification failed.\n");
    return 1;
  }

  zkp_double_el_gamal_copy(party->pi_chi_agg_proof, party->pi_chi_local_agg_proof);
  zkp_double_el_gamal_aggregate_local_proofs(party->pi_chi_agg_proof, pi_chi_local_proofs, num_parties-1);
  
  if (zkp_double_el_gamal_verify(party->pi_chi_agg_proof, &party->pi_chi_agg_public, party->aux) != 1) {
    printf("Aggregated Chi ZKP Double El Gamal verification failed.\n");
    return 1;
  }

  zkp_well_formed_signature_copy(party->pi_sig_agg_proof, party->pi_sig_local_agg_proof);
  zkp_well_formed_signature_aggregate_local_proofs(party->pi_sig_agg_proof, pi_sig_local_proofs, num_parties-1, party->paillier_pub[0]);

  if (zkp_well_formed_signature_verify(party->pi_sig_agg_proof, &party->pi_sig_agg_public, party->aux, bitlen_plus_1_num_parties) != 1) {
    printf("Aggregated ZKP Well Formed Signature verification failed.\n");
    return 1;
  }

  free(pi_eph_local_proofs);
  free(pi_chi_local_proofs);
  free(pi_sig_local_proofs);

  return 0;
}


uint64_t asymoff_signing_aggregate_send_msg_offline(asymoff_sign_agg_data_t *sender, asymoff_sign_agg_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i != 0) return 0;

  asymoff_sign_agg_msg_offline_t *in_msg_offline = receiver->in_aggregate_msg_offline;

  in_msg_offline->pi_eph_agg_proof = sender->pi_eph_agg_proof;
  in_msg_offline->pi_chi_agg_proof = sender->pi_chi_agg_proof;
  in_msg_offline->pi_sig_agg_proof = sender->pi_sig_agg_proof;

  in_msg_offline->R        = sender->R;
  in_msg_offline->joint_V1 = sender->joint_V1;
  in_msg_offline->joint_V2 = sender->joint_V2;
  in_msg_offline->packed_S = sender->pi_sig_agg_public.packed_S;
  in_msg_offline->packed_Z = sender->pi_sig_agg_public.packed_Z;
  
  return zkp_el_gamal_dlog_proof_bytelen(sender->num_sigs, 1) + zkp_double_el_gamal_proof_bytelen() + zkp_well_formed_signature_proof_bytelen(PACKING_SIZE) + sender->num_sigs*3*GROUP_ELEMENT_BYTES + (sender->num_sigs/PACKING_SIZE) *(RING_PED_MODULUS_BYTES + 2*PAILLIER_MODULUS_BYTES);
}


int verify_ecdsa_signature(const scalar_t r, const scalar_t s, const scalar_t msg, const gr_elem_t pubkey, ec_group_t ec, gr_elem_t ec_gen)
{
  scalar_t ec_order = ec_group_order(ec);

  gr_elem_t result = group_elem_new(ec);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t s_inv = scalar_new();
  scalar_inv(s_inv, s, ec_order, bn_ctx);

  group_operation(result, NULL, msg, pubkey, r, ec, bn_ctx);
  group_operation(result, NULL, NULL, result, s_inv, ec, bn_ctx);

  scalar_t project_x = scalar_new();
  group_elem_get_x(project_x, result, ec, ec_order);

  int is_valid = scalar_equal(project_x, r);

  group_elem_free(result);
  scalar_free(s_inv);
  scalar_free(project_x);

  BN_CTX_free(bn_ctx);

  return is_valid;
}

int asymoff_signing_aggregate_execute_offline (asymoff_sign_agg_data_t *party, scalar_t *signature_s) {
  if (party->i != 0) return 1;
  
  pinfo("Player %ld: Executing Offline Round\n", party->i);

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs = party->num_sigs;

  // Helper value for ZKP well formed sig: #bits + 1 of num_parties;
  int bitlen_plus_1_num_parties = 1;
  uint64_t target_next = 1;
  while (target_next <= num_parties) {
    target_next *= 2;
    ++bitlen_plus_1_num_parties;
  }

  ec_group_t ec = party->ec;
  scalar_t ec_order = ec_group_order(ec);
  
  asymoff_sign_agg_msg_offline_t *msg = party->in_aggregate_msg_offline;

  for (uint64_t l = 0; l < num_sigs; ++l) {
    if (group_elem_is_ident(msg->R[l], ec) == 1) {
        printf("Invalid identity nonce R for message #%ld.\n", l);
        return 1; 
    }
  }

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->num_parties, sizeof(uint64_t));

  zkp_el_gamal_dlog_public_t pi_eph_agg_public;

  pi_eph_agg_public.batch_size = num_sigs;
  pi_eph_agg_public.ec = party->ec;
  pi_eph_agg_public.R  = msg->R;
  pi_eph_agg_public.Y  = party->Y;
  pi_eph_agg_public.H  = party->H;
  pi_eph_agg_public.B1 = party->joint_B1;
  pi_eph_agg_public.B2 = party->joint_B2;

  if (zkp_el_gamal_dlog_verify(msg->pi_eph_agg_proof, &pi_eph_agg_public, party->aux, 0) != 1) {
    printf("Aggregated ZKP Ephemeral El Gamal DLog verification failed.\n");
    return 1;
  }

  zkp_double_el_gamal_public_t pi_chi_agg_public;

  pi_chi_agg_public.batch_size = num_sigs;
  pi_chi_agg_public.ec = party->ec;
  pi_chi_agg_public.X  = party->online_X;
  pi_chi_agg_public.Y  = party->Y;
  pi_chi_agg_public.B1 = party->joint_B1;
  pi_chi_agg_public.B2 = party->joint_B2;
  pi_chi_agg_public.V1 = msg->joint_V1;
  pi_chi_agg_public.V2 = msg->joint_V2;
  
  if (zkp_double_el_gamal_verify(msg->pi_chi_agg_proof, &pi_chi_agg_public, party->aux) != 1) {
    printf("Aggregated Chi ZKP Double El Gamal verification failed.\n");
    return 1;
  }

  zkp_well_formed_signature_public_t pi_sig_agg_public;

  pi_sig_agg_public.batch_size = num_sigs;
  pi_sig_agg_public.packing_size = PACKING_SIZE;
  pi_sig_agg_public.paillier_pub = party->paillier_pub[0];
  pi_sig_agg_public.rped_pub = party->rped_pub[0];
  pi_sig_agg_public.ec = party->ec;
  pi_sig_agg_public.Y  = party->Y;
  pi_sig_agg_public.W  = party->W_0;

  pi_sig_agg_public.packed_S = msg->packed_S;
  pi_sig_agg_public.packed_Z = msg->packed_Z;

  pi_sig_agg_public.U1 = gr_el_array_new(num_sigs, ec);
  pi_sig_agg_public.U2 = gr_el_array_new(num_sigs, ec);
  pi_sig_agg_public.L1 = gr_el_array_new(num_sigs, ec);
  pi_sig_agg_public.L2 = gr_el_array_new(num_sigs, ec);

  scalar_t r = scalar_new();

  for (uint64_t l = 0; l < num_sigs; ++l) {
    group_elem_get_x(r, msg->R[l], ec, ec_order);
    group_operation(pi_sig_agg_public.L1[l], NULL, NULL, party->joint_B1[l], r, ec, bn_ctx);
    
    group_operation(pi_sig_agg_public.L2[l], NULL, NULL, party->joint_B2[l], r, ec, bn_ctx);
    
    group_operation(pi_sig_agg_public.U1[l], NULL, NULL, party->joint_B1[l], party->msgs[l], ec, bn_ctx);
    group_operation(pi_sig_agg_public.U1[l], pi_sig_agg_public.U1[l], NULL, msg->joint_V1[l], r, ec, bn_ctx);
    
    group_operation(pi_sig_agg_public.U2[l], NULL, NULL, party->joint_B2[l], party->msgs[l], ec, bn_ctx);
    group_operation(pi_sig_agg_public.U2[l], pi_sig_agg_public.U2[l], NULL, msg->joint_V2[l], r, ec, bn_ctx);
  }

  if (zkp_well_formed_signature_verify(msg->pi_sig_agg_proof, &pi_sig_agg_public, party->aux, bitlen_plus_1_num_parties) != 1) {
    printf("Aggregated ZKP Well Formed Signature verification failed.\n");
    return 1;
  }

  scalar_t dec_packed_sigma = scalar_new();
  scalar_t temp = scalar_new();

  gr_elem_t pubkey_X = group_elem_new(ec);
  group_operation(pubkey_X, party->online_X, NULL, party->X[0], NULL, ec, bn_ctx);
  
  for (uint64_t l = 0; l < num_sigs/PACKING_SIZE; ++l) {
    paillier_encryption_decrypt(dec_packed_sigma, msg->packed_Z[l], party->paillier_offline_priv);
    unpack_plaintexts(&party->signature_sigma[PACKING_SIZE*l], PACKING_SIZE, dec_packed_sigma);
  }

  for (uint64_t l = 0; l < num_sigs; ++l) {
    scalar_inv(temp, party->nonce[l], ec_order, bn_ctx);
    scalar_mul(party->signature_sigma[l], party->signature_sigma[l], temp, ec_order, bn_ctx);
    
    group_elem_get_x(r, msg->R[l], ec, ec_order);

    if (verify_ecdsa_signature(r, party->signature_sigma[l], party->msgs[l], pubkey_X, ec, ec_group_generator(ec)) != 1) {
      printf("Invalid signature #%ld\n", l);
      return 1;
    }
  }

  scalar_array_copy(signature_s, party->signature_sigma, num_sigs);

  group_elem_free(pubkey_X);
  scalar_free(dec_packed_sigma);
  scalar_free(temp);
  scalar_free(r);
  gr_el_array_free(pi_sig_agg_public.U1, num_sigs);
  gr_el_array_free(pi_sig_agg_public.U2, num_sigs);
  gr_el_array_free(pi_sig_agg_public.L1, num_sigs);
  gr_el_array_free(pi_sig_agg_public.L2, num_sigs);
  BN_CTX_free(bn_ctx);

  return 0;
}