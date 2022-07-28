#include "asymoff_signing_cmp.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

asymoff_sign_cmp_data_t **asymoff_signing_cmp_parties_new(asymoff_party_data_t ** parties, uint64_t num_sigs) {

  uint64_t num_parties = parties[0]->num_parties;
  
  assert(num_parties >= 2);

  for (uint64_t i = 0; i < num_parties; ++i) {
      if (parties[i]->curr_index + num_sigs > parties[i]->batch_size)
      {
        printf("Signing CMP: Party %ld can't sign %ld signature. Batch size: %ld, curr index: %ld.\n", num_sigs, i, parties[i]->batch_size, parties[i]->curr_index); 
        return NULL;
      }

  }

  // Update all indices, assumes all previous were consumed already
  // Note: Offline Party in practice can only update after end of signing aggregate

  for (uint64_t i = 0; i < num_parties; ++i) {

    parties[i]->num_sigs = num_sigs;
    parties[i]->curr_index = parties[i]->next_index;
    parties[i]->next_index = parties[i]->curr_index + num_sigs;
  }

  asymoff_sign_cmp_data_t **cmp_parties = calloc(num_parties, sizeof(asymoff_sign_cmp_data_t *));
  
  for (uint64_t i = 1; i < num_parties; ++i) {
    
    uint64_t curr_index = parties[i]->curr_index;  

    ec_group_t ec = parties[i]->ec;

    cmp_parties[i] = malloc(sizeof(asymoff_sign_cmp_data_t));

    asymoff_sign_cmp_data_t *party = cmp_parties[i];

    party->i = i;
    party->num_parties = num_parties;
    party->num_sigs = num_sigs;

    party->ec = ec;
    party->gen = parties[i]->gen;
    party->Y = parties[i]->Y;
    party->X = parties[i]->X;
    party->x = parties[i]->x;

    party->online_X = group_elem_new(ec);
    group_operation(party->online_X, NULL ,NULL, NULL, ec);
    for (uint64_t i = 1; i < num_parties; ++i) group_operation(party->online_X, party->online_X, party->X[i], NULL, ec);
    
    party->paillier_priv  = parties[i]->paillier_priv;
    party->paillier_pub   = parties[i]->paillier_pub;
    party->rped_pub       = parties[i]->rped_pub;

    uint64_t aux_pos = 0;
    party->aux = zkp_aux_info_new(2*sizeof(hash_chunk) + sizeof(uint64_t), NULL);
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->sid, sizeof(hash_chunk));
    zkp_aux_info_update_move(party->aux, &aux_pos, &party->i, sizeof(uint64_t));
    zkp_aux_info_update_move(party->aux, &aux_pos, parties[i]->srid, sizeof(hash_chunk));
    assert(party->aux->info_len == aux_pos);

    party->R      = new_gr_el_array(num_sigs, ec);
    party->chi    = new_scalar_array(num_sigs);
    
    party->nonce  = &parties[i]->nonce[curr_index];
    party->b      = &parties[i]->b[curr_index];
    party->H      = &parties[i]->H[curr_index];

    party->B1 = calloc(num_parties, sizeof(gr_elem_t *));
    party->B2 = calloc(num_parties, sizeof(gr_elem_t *));

    for (uint64_t j = 1; j < num_parties; ++j) {
      party->B1[j] = &parties[i]->B1[j][curr_index];
      party->B2[j] = &parties[i]->B2[j][curr_index];
    }

    party->G      = new_scalar_array(num_sigs);
    party->K      = new_scalar_array(num_sigs);
    party->rho    = new_scalar_array(num_sigs);
    party->nu     = new_scalar_array(num_sigs);
    party->z      = new_scalar_array(num_sigs);
    party->delta  = new_scalar_array(num_sigs);
    party->gamma  = new_scalar_array(num_sigs);

    party->H_gamma  = new_gr_el_array(num_sigs, ec);
    party->Delta    = new_gr_el_array(num_sigs, ec);
    party->Gamma1   = new_gr_el_array(num_sigs, ec);
    party->Gamma2   = new_gr_el_array(num_sigs, ec);
    party->Lambda   = new_gr_el_array(num_sigs, ec);

    party->beta       = calloc(num_parties, sizeof(gr_elem_t*));
    party->D          = calloc(num_parties, sizeof(gr_elem_t*));
    party->F          = calloc(num_parties, sizeof(gr_elem_t*));
    party->beta_hat   = calloc(num_parties, sizeof(gr_elem_t*));
    party->D_hat      = calloc(num_parties, sizeof(gr_elem_t*));
    party->F_hat      = calloc(num_parties, sizeof(gr_elem_t*));

    for (uint64_t j = 1; j < num_parties; ++j) {

      party->beta[j]     = new_scalar_array(num_sigs);
      party->D[j]        = new_scalar_array(num_sigs);
      party->F[j]        = new_scalar_array(num_sigs);
      party->beta_hat[j] = new_scalar_array(num_sigs);
      party->D_hat[j]    = new_scalar_array(num_sigs);
      party->F_hat[j]    = new_scalar_array(num_sigs);
    }

    party->phi_ddh_H_Gamma  = zkp_el_gamal_dlog_new(num_sigs, ec);
    party->psi_ddh_Delta        = zkp_el_gamal_dlog_new(num_sigs, ec);

    party->theta_Rddh_G   = calloc(num_parties, sizeof(zkp_range_el_gamal_proof_t*));
    party->theta_Rddh_K   = calloc(num_parties, sizeof(zkp_range_el_gamal_proof_t*));
    party->phi_affg_X     = calloc(num_parties, sizeof(zkp_oper_group_commit_range_proof_t*));
    party->phi_affg_H     = calloc(num_parties, sizeof(zkp_oper_group_commit_range_proof_t*));

    for (uint64_t j = 1; j < num_parties; ++j) {
      party->theta_Rddh_G[j] = zkp_range_el_gamal_new(num_sigs, 1, ec);
      party->theta_Rddh_K[j] = zkp_range_el_gamal_new(num_sigs, 1, ec);

      party->phi_affg_X[j] = calloc(num_sigs, sizeof(zkp_oper_group_commit_range_proof_t*));
      party->phi_affg_H[j] = calloc(num_sigs, sizeof(zkp_oper_group_commit_range_proof_t*));

      for (uint64_t l = 0; l < num_sigs; ++l) {
        party->phi_affg_X[j][l] = zkp_oper_group_commit_range_new(ec);
        party->phi_affg_H[j][l] = zkp_oper_group_commit_range_new(ec);
      }
    }

    party->in_cmp_msg_1 = calloc(num_parties, sizeof(asymoff_sign_cmp_msg_round_1_t));
    party->in_cmp_msg_2 = calloc(num_parties, sizeof(asymoff_sign_cmp_msg_round_2_t));
    party->in_cmp_msg_3 = calloc(num_parties, sizeof(asymoff_sign_cmp_msg_round_3_t));
  }
  
  return cmp_parties;
}

void asymoff_signing_cmp_parties_free(asymoff_sign_cmp_data_t **cmp_parties) {

  uint64_t num_parties = cmp_parties[1]->num_parties;

  for (uint64_t i = 1; i < num_parties; ++i) {
    
    uint64_t num_sigs = cmp_parties[i]->num_sigs;

    asymoff_sign_cmp_data_t *party = cmp_parties[i];

    zkp_aux_info_free(party->aux);

    group_elem_free(party->online_X);

    free_gr_el_array(party->R   , num_sigs);
    free_scalar_array(party->chi, num_sigs);
    
    free(party->B1);
    free(party->B2);

    free_scalar_array(party->G    , num_sigs);
    free_scalar_array(party->K    , num_sigs);
    free_scalar_array(party->rho  , num_sigs);
    free_scalar_array(party->nu   , num_sigs);
    free_scalar_array(party->z    , num_sigs);
    free_scalar_array(party->delta, num_sigs);
    free_scalar_array(party->gamma, num_sigs);

    free_gr_el_array(party->H_gamma, num_sigs);
    free_gr_el_array(party->Delta  , num_sigs);
    free_gr_el_array(party->Gamma1 , num_sigs);
    free_gr_el_array(party->Gamma2 , num_sigs);
    free_gr_el_array(party->Lambda , num_sigs);

    for (uint64_t j = 1; j < num_parties; ++j) {

      free_scalar_array(party->beta[j]    , num_sigs);
      free_scalar_array(party->D[j]       , num_sigs);
      free_scalar_array(party->F[j]       , num_sigs);
      free_scalar_array(party->beta_hat[j], num_sigs);
      free_scalar_array(party->D_hat[j]   , num_sigs);
      free_scalar_array(party->F_hat[j]   , num_sigs);
    }


    free(party->beta);
    free(party->D);
    free(party->F);
    free(party->beta_hat);
    free(party->D_hat);
    free(party->F_hat);

    zkp_el_gamal_dlog_free(party->phi_ddh_H_Gamma);
    zkp_el_gamal_dlog_free(party->psi_ddh_Delta);

    for (uint64_t j = 1; j < num_parties; ++j) {

      zkp_range_el_gamal_free(party->theta_Rddh_G[j]);
      zkp_range_el_gamal_free(party->theta_Rddh_K[j]);

      for (uint64_t l = 0; l < num_sigs; ++l) {
        zkp_oper_group_commit_range_free(party->phi_affg_X[j][l]);
        zkp_oper_group_commit_range_free(party->phi_affg_H[j][l]);
      }

      free(party->phi_affg_X[j]);
      free(party->phi_affg_H[j]);
    }

    free(party->theta_Rddh_G);
    free(party->theta_Rddh_K);
    free(party->phi_affg_X  );
    free(party->phi_affg_H  );

    free(party->in_cmp_msg_1);
    free(party->in_cmp_msg_2);
    free(party->in_cmp_msg_3);

    free(cmp_parties[i]);
  }
  
  free(cmp_parties);
}

int asymoff_signing_cmp_execute_round_1(asymoff_sign_cmp_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Round 1\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs = party->num_sigs;
  ec_group_t ec = party->ec;
  scalar_t ec_order = ec_group_order(ec);

  paillier_public_key_t *my_paillier_pub = party->paillier_pub[party->i];

  for (uint64_t l = 0; l < num_sigs; ++l) {

    paillier_encryption_sample(party->rho[l], my_paillier_pub);
    paillier_encryption_encrypt(party->K[l], party->nonce[l], party->rho[l], my_paillier_pub);

    scalar_sample_in_range(party->gamma[l], ec_order, 0);
    group_operation(party->H_gamma[l], NULL, party->H[l], party->gamma[l], party->ec);

    paillier_encryption_sample(party->nu[l], my_paillier_pub);
    paillier_encryption_encrypt(party->G[l], party->gamma[l], party->nu[l], my_paillier_pub);

    scalar_sample_in_range(party->z[l], ec_order, 0);

    group_operation(party->Gamma1[l], NULL, party->gen, party->z[l], ec);

    group_operation(party->Gamma2[l], NULL, party->gen, party->gamma[l], ec);
    group_operation(party->Gamma2[l], party->Gamma2[l], party->Y, party->z[l], ec);
  }

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));

  zkp_range_el_gamal_public_t theta_Rddh_public;
  zkp_range_el_gamal_secret_t theta_Rddh_secret;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue; 

    theta_Rddh_public.batch_size    = num_sigs;
    theta_Rddh_public.packing_size  = 1;
    theta_Rddh_public.paillier_pub  = my_paillier_pub;
    theta_Rddh_public.rped_pub      = party->rped_pub[j];
    theta_Rddh_public.Y             = party->Y;
    theta_Rddh_public.ec            = party->ec;
    theta_Rddh_public.g             = party->gen;

    // theta proof for K

    theta_Rddh_public.packed_C  = party->K;
    theta_Rddh_public.A1        = party->B1[party->i];
    theta_Rddh_public.A2        = party->B2[party->i];

    theta_Rddh_secret.b   = party->b;
    theta_Rddh_secret.rho = party->rho;
    theta_Rddh_secret.x   = party->nonce;

    zkp_range_el_gamal_prove(party->theta_Rddh_K[j], &theta_Rddh_secret, &theta_Rddh_public, party->aux);

    // theta proof for G

    theta_Rddh_public.packed_C  = party->G;
    theta_Rddh_public.A1        = party->Gamma1;
    theta_Rddh_public.A2        = party->Gamma2;

    theta_Rddh_secret.b = party->z;
    theta_Rddh_secret.rho = party->nu;
    theta_Rddh_secret.x = party->gamma;

    zkp_range_el_gamal_prove(party->theta_Rddh_G[j], &theta_Rddh_secret, &theta_Rddh_public, party->aux);
  }

  // TODO: no broadcast of K,G?

  return 0;
}

uint64_t asymoff_signing_cmp_send_msg_1(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_cmp_msg_round_1_t *in_cmp_msg_1 = &receiver->in_cmp_msg_1[sender->i];

  in_cmp_msg_1->K = sender->K;
  in_cmp_msg_1->G = sender->G;
  in_cmp_msg_1->Gamma1 = sender->Gamma1;
  in_cmp_msg_1->Gamma2 = sender->Gamma2;
  in_cmp_msg_1->theta_Rddh_K = sender->theta_Rddh_K[receiver->i];
  in_cmp_msg_1->theta_Rddh_G = sender->theta_Rddh_G[receiver->i];

  return sender->num_sigs*(2*PAILLIER_MODULUS_BYTES + 2*GROUP_ELEMENT_BYTES) + 2*(sender->num_parties-1)*zkp_range_el_gamal_proof_bytelen(sender->num_sigs, 1);
}

int asymoff_signing_cmp_execute_round_2(asymoff_sign_cmp_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Round 2\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs    = party->num_sigs;

  asymoff_sign_cmp_msg_round_1_t *in_cmp_msg_1;

  zkp_range_el_gamal_public_t theta_Rddh_public;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue; 

    in_cmp_msg_1 = &party->in_cmp_msg_1[j];

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));

    theta_Rddh_public.batch_size    = num_sigs;
    theta_Rddh_public.packing_size  = 1;
    theta_Rddh_public.paillier_pub  = party->paillier_pub[j];
    theta_Rddh_public.rped_pub      = party->rped_pub[party->i];
    theta_Rddh_public.Y             = party->Y;
    theta_Rddh_public.ec            = party->ec;
    theta_Rddh_public.g             = party->gen;

    // Verify K proof

    theta_Rddh_public.packed_C  = in_cmp_msg_1->K;
    theta_Rddh_public.A1        = party->B1[j];
    theta_Rddh_public.A2        = party->B2[j];

    if (zkp_range_el_gamal_verify(in_cmp_msg_1->theta_Rddh_K, &theta_Rddh_public, party->aux) != 1) {
      printf("K ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", j);
      return 1;
    }

    // Verify G proof

    theta_Rddh_public.packed_C  = in_cmp_msg_1->G;
    theta_Rddh_public.A1        = in_cmp_msg_1->Gamma1;
    theta_Rddh_public.A2        = in_cmp_msg_1->Gamma2;

    if (zkp_range_el_gamal_verify(in_cmp_msg_1->theta_Rddh_G, &theta_Rddh_public, party->aux) != 1) {
      printf("G ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", j);
      return 1;
    }
  }

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));

  // Prove H/H_gamma/Gamma

  zkp_el_gamal_dlog_public_t phi_eph_public;
  phi_eph_public.batch_size = num_sigs;
  phi_eph_public.B1 = party->Gamma1;
  phi_eph_public.B2 = party->Gamma2;
  phi_eph_public.H  = party->H_gamma;
  phi_eph_public.R  = party->H;
  phi_eph_public.ec = party->ec;
  phi_eph_public.g  = party->gen;
  phi_eph_public.Y  = party->Y;

  zkp_el_gamal_dlog_secret_t phi_eph_secret;
  phi_eph_secret.lambda = new_scalar_array(num_sigs);
  phi_eph_secret.rho    = new_scalar_array(num_sigs);
  phi_eph_secret.k      = party->gamma;
  phi_eph_secret.b      = party->z;
  
  zkp_el_gamal_dlog_anchor(party->phi_ddh_H_Gamma, &phi_eph_secret, &phi_eph_public);
  zkp_el_gamal_dlog_prove(party->phi_ddh_H_Gamma, &phi_eph_secret, &phi_eph_public, party->aux, 1);

  free_scalar_array(phi_eph_secret.lambda, num_sigs);
  free_scalar_array(phi_eph_secret.rho, num_sigs);

  // Executing MtA with corresponding ZKP

  scalar_t r          = scalar_new();
  scalar_t s          = scalar_new();
  scalar_t temp_enc   = scalar_new();
  scalar_t beta_range = scalar_new();

  scalar_set_power_of_2(beta_range, 8*CALIGRAPHIC_J_ZKP_RANGE_BYTES);

  zkp_oper_group_commit_range_public_t phi_affg_public;
  phi_affg_public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
  phi_affg_public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES;  
  phi_affg_public.paillier_pub_1 = party->paillier_pub[party->i];
  phi_affg_public.G = party->ec;

  zkp_oper_group_commit_range_secret_t phi_affg_secret;

  for (uint64_t j = 1; j < party->num_parties; ++j)
  {
    if (party->i == j) continue;

    in_cmp_msg_1 = &party->in_cmp_msg_1[j];

    phi_affg_public.paillier_pub_0 = party->paillier_pub[j];
    phi_affg_public.rped_pub = party->rped_pub[j];

    for (uint64_t l = 0; l < num_sigs; ++l) {

      // Mta - part 1: compute

      scalar_sample_in_range(party->beta[j][l], beta_range, 0);
      scalar_make_signed(party->beta[j][l], beta_range);

      paillier_encryption_sample(r, party->paillier_pub[party->i]);
      paillier_encryption_encrypt(party->F[j][l], party->beta[j][l], r, party->paillier_pub[party->i]);

      paillier_encryption_sample(s, party->paillier_pub[j]);
      paillier_encryption_encrypt(temp_enc, party->beta[j][l], s, party->paillier_pub[j]);
      paillier_encryption_homomorphic(party->D[j][l], in_cmp_msg_1->K[l], party->x, temp_enc, party->paillier_pub[j]);

      // Mta - part 1: prove

      phi_affg_public.X = party->X[party->i];
      phi_affg_public.C = in_cmp_msg_1->K[l];
      phi_affg_public.D = party->D[j][l];
      phi_affg_public.Y = party->F[j][l];
      phi_affg_public.g = party->gen;

      phi_affg_secret.rho_y = r;
      phi_affg_secret.rho = s;
      phi_affg_secret.x = party->x;
      phi_affg_secret.y = party->beta[j][l];

      zkp_oper_group_commit_range_prove(party->phi_affg_X[j][l], &phi_affg_secret, &phi_affg_public, party->aux);

      // Mta - part 2: compute

      scalar_sample_in_range(party->beta_hat[j][l], beta_range, 0);
      scalar_make_signed(party->beta_hat[j][l], beta_range);
      paillier_encryption_sample(r, party->paillier_pub[party->i]);
      paillier_encryption_encrypt(party->F_hat[j][l], party->beta_hat[j][l], r, party->paillier_pub[party->i]);

      paillier_encryption_sample(s, party->paillier_pub[j]);
      paillier_encryption_encrypt(temp_enc, party->beta_hat[j][l], s, party->paillier_pub[j]);
      paillier_encryption_homomorphic(party->D_hat[j][l], in_cmp_msg_1->K[l], party->gamma[l], temp_enc, party->paillier_pub[j]);

      // Mta - part 2: prove

      phi_affg_public.X = party->H_gamma[l];
      phi_affg_public.C = in_cmp_msg_1->K[l];
      phi_affg_public.D = party->D_hat[j][l];
      phi_affg_public.Y = party->F_hat[j][l];
      phi_affg_public.g = party->H[l];

      phi_affg_secret.rho_y = r;
      phi_affg_secret.rho = s;
      phi_affg_secret.x = party->gamma[l];
      phi_affg_secret.y = party->beta_hat[j][l];
      
      zkp_oper_group_commit_range_prove(party->phi_affg_H[j][l], &phi_affg_secret, &phi_affg_public, party->aux);
    }
  }

  scalar_free(beta_range);
  scalar_free(temp_enc);
  scalar_free(r);
  scalar_free(s);


  return 0;
}

uint64_t asymoff_signing_cmp_send_msg_2(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_cmp_msg_round_2_t *in_cmp_msg_2 = &receiver->in_cmp_msg_2[sender->i];

  in_cmp_msg_2->H_gamma = sender->H_gamma;
  in_cmp_msg_2->D       = sender->D[receiver->i];
  in_cmp_msg_2->F       = sender->F[receiver->i];
  in_cmp_msg_2->D_hat   = sender->D_hat[receiver->i];
  in_cmp_msg_2->F_hat   = sender->F_hat[receiver->i];

  in_cmp_msg_2->phi_ddh_H_gamma = sender->phi_ddh_H_Gamma;
  in_cmp_msg_2->phi_affg_X      = sender->phi_affg_X[receiver->i];
  in_cmp_msg_2->phi_affg_H      = sender->phi_affg_H[receiver->i];

  return zkp_el_gamal_dlog_proof_bytelen(sender->num_sigs, 1) + sender->num_sigs*(GROUP_ELEMENT_BYTES + 4*PAILLIER_MODULUS_BYTES + 2*(sender->num_parties-1)*zkp_oper_group_commit_range_bytelen(CALIGRAPHIC_I_ZKP_RANGE_BYTES, CALIGRAPHIC_J_ZKP_RANGE_BYTES));
}


int asymoff_signing_cmp_execute_round_3(asymoff_sign_cmp_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Round 3\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs    = party->num_sigs;

  asymoff_sign_cmp_msg_round_1_t *in_cmp_msg_1;
  asymoff_sign_cmp_msg_round_2_t *in_cmp_msg_2;

  zkp_oper_group_commit_range_public_t phi_affg_public;
  phi_affg_public.x_range_bytes = CALIGRAPHIC_I_ZKP_RANGE_BYTES;
  phi_affg_public.y_range_bytes = CALIGRAPHIC_J_ZKP_RANGE_BYTES; 
  phi_affg_public.paillier_pub_0 = party->paillier_pub[party->i];
  phi_affg_public.rped_pub       = party->rped_pub[party->i];
  phi_affg_public.G = party->ec;
  
  zkp_el_gamal_dlog_public_t phi_eph_public;
  phi_eph_public.batch_size = num_sigs;
  phi_eph_public.R  = party->H;
  phi_eph_public.ec = party->ec;
  phi_eph_public.g  = party->gen;
  phi_eph_public.Y  = party->Y;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue;

    in_cmp_msg_1 = &party->in_cmp_msg_1[j];
    in_cmp_msg_2 = &party->in_cmp_msg_2[j];

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));

    phi_eph_public.B1 = in_cmp_msg_1->Gamma1;
    phi_eph_public.B2 = in_cmp_msg_1->Gamma2;
    phi_eph_public.H  = in_cmp_msg_2->H_gamma;

    if (zkp_el_gamal_dlog_verify(in_cmp_msg_2->phi_ddh_H_gamma, &phi_eph_public, party->aux, 1) != 1) {
        printf("ZKP El Gamal Dlog (H vs H_gamma vs Gamma) verification failed. Received from party %ld\n", j);
        return 1;
    }

    // Verify affince proofs

    phi_affg_public.paillier_pub_1 = party->paillier_pub[j];

    for (uint64_t l = 0; l < num_sigs; ++l) {

      phi_affg_public.X = party->X[j];
      phi_affg_public.C = party->K[l];
      phi_affg_public.D = in_cmp_msg_2->D[l];
      phi_affg_public.Y = in_cmp_msg_2->F[l];
      phi_affg_public.g = party->gen;

      if (zkp_oper_group_commit_range_verify(in_cmp_msg_2->phi_affg_X[l], &phi_affg_public, party->aux) != 1) {
        printf("X ZKP Affine Operation vs Group Commitment in Range verification failed. Received from party %ld\n", j);
        return 1;
      }
    
      phi_affg_public.X = in_cmp_msg_2->H_gamma[l];
      phi_affg_public.C = party->K[l];
      phi_affg_public.D = in_cmp_msg_2->D_hat[l];
      phi_affg_public.Y = in_cmp_msg_2->F_hat[l];
      phi_affg_public.g = party->H[l];

      if (zkp_oper_group_commit_range_verify(in_cmp_msg_2->phi_affg_H[l], &phi_affg_public, party->aux) != 1) {
        printf("K ZKP Affine Operation vs Group Commitment in Range verification failed. Received from party %ld\n", j);
        return 1;
      }
    }
  }


  scalar_t ec_order = ec_group_order(party->ec);
  scalar_t alpha = scalar_new();

  for (uint64_t l = 0; l < num_sigs; ++l) {

     // Initalize delta, chi, Lambda

    group_elem_copy(party->Lambda[l], party->H_gamma[l]);
    scalar_mul(party->chi[l], party->x, party->nonce[l], ec_order);
    scalar_mul(party->delta[l], party->gamma[l], party->nonce[l], ec_order);

    for (uint64_t j = 1; j < num_parties; ++j) {
      if (party->i == j) continue;

      in_cmp_msg_1 = &party->in_cmp_msg_1[j];
      in_cmp_msg_2 = &party->in_cmp_msg_2[j];

      // Aggregate Lambda

      group_operation(party->Lambda[l], party->Lambda[l], in_cmp_msg_2->H_gamma[l], NULL, party->ec);
      
      // Compute chi_i

      paillier_encryption_decrypt(alpha, in_cmp_msg_2->D[l], party->paillier_priv);
      scalar_make_signed(alpha, party->paillier_pub[party->i]->N);
      scalar_add(party->chi[l], party->chi[l], alpha, ec_order);
      scalar_sub(party->chi[l], party->chi[l], party->beta[j][l], ec_order);

       // Compute delta_i

      paillier_encryption_decrypt(alpha, in_cmp_msg_2->D_hat[l], party->paillier_priv);
      scalar_make_signed(alpha, party->paillier_pub[party->i]->N);
      scalar_add(party->delta[l], party->delta[l], alpha, ec_order);
      scalar_sub(party->delta[l], party->delta[l], party->beta_hat[j][l], ec_order);

    }

    group_operation(party->Delta[l], NULL, party->Lambda[l], party->nonce[l], party->ec);
  }

  scalar_free(alpha);

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));

  // Prove Lambda/Delta/B

  zkp_el_gamal_dlog_public_t psi_ddh_public;
  psi_ddh_public.batch_size = num_sigs;
  psi_ddh_public.B1 = party->B1[party->i];
  psi_ddh_public.B2 = party->B2[party->i];
  psi_ddh_public.H  = party->Delta;
  psi_ddh_public.R  = party->Lambda;
  psi_ddh_public.ec = party->ec;
  psi_ddh_public.g  = party->gen;
  psi_ddh_public.Y  = party->Y;

  zkp_el_gamal_dlog_secret_t psi_ddh_secret;
  psi_ddh_secret.lambda = new_scalar_array(num_sigs);
  psi_ddh_secret.rho    = new_scalar_array(num_sigs);
  psi_ddh_secret.k      = party->nonce;
  psi_ddh_secret.b      = party->b;
  
  zkp_el_gamal_dlog_anchor(party->psi_ddh_Delta, &psi_ddh_secret, &psi_ddh_public);
  zkp_el_gamal_dlog_prove(party->psi_ddh_Delta, &psi_ddh_secret, &psi_ddh_public, party->aux, 1);

  free_scalar_array(psi_ddh_secret.lambda, num_sigs);
  free_scalar_array(psi_ddh_secret.rho, num_sigs);

  return 0;
}

uint64_t asymoff_signing_cmp_send_msg_3(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_sign_cmp_msg_round_3_t *in_cmp_msg_3 = &receiver->in_cmp_msg_3[sender->i];

  in_cmp_msg_3->delta = sender->delta;
  in_cmp_msg_3->Delta = sender->Delta;
  in_cmp_msg_3->psi_ddh_Delta = sender->psi_ddh_Delta;
  
  return sender->num_sigs*( GROUP_ORDER_BYTES + GROUP_ELEMENT_BYTES) + zkp_el_gamal_dlog_proof_bytelen(sender->num_sigs, 1);
}

int asymoff_signing_cmp_execute_final(asymoff_sign_cmp_data_t *party) {
  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Finalization\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t num_sigs    = party->num_sigs;


  scalar_t *joint_delta = new_scalar_array(num_sigs);
  gr_elem_t *joint_Delta = new_gr_el_array(num_sigs, party->ec);

  copy_scalar_array(joint_delta, party->delta, num_sigs);
  copy_gr_el_array(joint_Delta, party->Delta, num_sigs);

  asymoff_sign_cmp_msg_round_3_t *in_cmp_msg_3;

  zkp_el_gamal_dlog_public_t psi_ddh_public;
  psi_ddh_public.batch_size = num_sigs;
  psi_ddh_public.R  = party->Lambda;
  psi_ddh_public.ec = party->ec;
  psi_ddh_public.g  = party->gen;
  psi_ddh_public.Y  = party->Y;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (party->i == j) continue;
    
    in_cmp_msg_3 = &party->in_cmp_msg_3[j];

    psi_ddh_public.B1 = party->B1[j];
    psi_ddh_public.B2 = party->B2[j];
    psi_ddh_public.H  = in_cmp_msg_3->Delta;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));

    if (zkp_el_gamal_dlog_verify(in_cmp_msg_3->psi_ddh_Delta, &psi_ddh_public, party->aux, 1) != 1) {
        printf("ZKP El Gamal Dlog (Delta vs Lambda vs B) verification failed. Received from party %ld\n", j);
        return 1;
    }

    for (uint64_t l = 0; l < num_sigs; ++l) {
      scalar_add(joint_delta[l], joint_delta[l], in_cmp_msg_3->delta[l], ec_group_order(party->ec));
      group_operation(joint_Delta[l], joint_Delta[l], in_cmp_msg_3->Delta[l], NULL, party->ec);
    }
  }

  // Verify equality of joint Delta and H^{joint_delta}
  gr_elem_t H_delta = group_elem_new(party->ec);
  scalar_t delta_inv = scalar_new();

  for (uint64_t l = 0; l < num_sigs; ++l) {

    group_operation(H_delta, NULL, party->H[l], joint_delta[l], party->ec);
    
    if (group_elem_equal(H_delta, joint_Delta[l], party->ec) != 1) {
      printf("Invalid H^{delta}, not same as joint Delta, for signature %ld in batch.\n", l);
      return 1;
    }

    scalar_inv(delta_inv, joint_delta[l], ec_group_order(party->ec));
    group_operation(party->R[l], NULL, party->Lambda[l], delta_inv, party->ec);
  }

  free_scalar_array(joint_delta, num_sigs);
  free_gr_el_array(joint_Delta, num_sigs);
  group_elem_free(H_delta);

  return 0;
}


void asymoff_signing_cmp_export_data(asymoff_party_data_t **parties, asymoff_sign_cmp_data_t ** const cmp_parties) {
  
  for (uint64_t j = 1; j < parties[0]->num_parties; ++j) {

    uint64_t num_sigs = cmp_parties[j]->num_sigs;

    copy_gr_el_array(&parties[j]->R[parties[j]->curr_index], cmp_parties[j]->R, num_sigs);
    copy_scalar_array(&parties[j]->chi[parties[j]->curr_index], cmp_parties[j]->chi, num_sigs);
  }
}

int asymoff_signing_cmp_execute_mock_export_data (asymoff_party_data_t **parties) {
 
  assert(parties[0]->num_parties >= 2);

  uint64_t num_parties  = parties[1]->num_parties;
  uint64_t num_sigs     = parties[1]->num_sigs;
  uint64_t curr_index   = parties[1]->curr_index;
  ec_group_t ec         = parties[1]->ec;

  scalar_t x          = scalar_new();
  scalar_t curr_k     = scalar_new();
  scalar_t curr_k_inv = scalar_new();

  scalar_set_ul(x, 0);
  for (uint64_t i = 1; i < num_parties; ++i) {
    scalar_add(x, x, parties[i]->x, ec_group_order(ec));
  }
  
  for (uint64_t l = curr_index; l < curr_index + num_sigs; ++l) {
    
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
