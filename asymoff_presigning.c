#include "asymoff_presigning.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

asymoff_presigning_data_t **asymoff_presigning_parties_new(asymoff_party_data_t ** const parties, uint64_t batch_size) 
{
  assert(batch_size % PACKING_SIZE == 0);

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
    party->gen = parties[i]->gen;
    party->Y = parties[i]->Y;
    
    party->paillier_pub = parties[i]->paillier_pub;
    party->rped_pub = parties[i]->rped_pub;

    if (i == 0) {

      party->offline = malloc(sizeof(asymoff_presigning_data_offline_t));

      asymoff_presigning_data_offline_t *offline = party->offline;

      offline->A1    = new_gr_el_array(batch_size, ec);
      offline->A2    = new_gr_el_array(batch_size, ec);
      offline->H     = new_gr_el_array(batch_size, ec);
      offline->alpha = new_scalar_array(batch_size);

      offline->Paillier_packed_C = new_scalar_array(batch_size/PACKING_SIZE);

      offline->phi_Rddh = calloc(num_parties, sizeof(zkp_range_el_gamal_proof_t*));
      for (uint64_t i = 0; i < num_parties; ++i) offline->phi_Rddh[i] = zkp_range_el_gamal_new(batch_size, PACKING_SIZE, ec);
      
      offline->phi_eph = zkp_el_gamal_dlog_new(batch_size, ec);

    } else { // i > 0

      party->online = malloc(sizeof(asymoff_presigning_data_online_t));

      asymoff_presigning_data_online_t *online = party->online;

      online->B1 = new_gr_el_array(batch_size, ec);
      online->B2 = new_gr_el_array(batch_size, ec);
      online->k  = new_scalar_array(batch_size);
      online->b  = new_scalar_array(batch_size);

      online->Paillier_packed_K = new_scalar_array(batch_size/PACKING_SIZE);

      online->phi_Rddh = calloc(num_parties, sizeof(zkp_range_el_gamal_proof_t*));
      for (uint64_t i = 0; i < num_parties; ++i) online->phi_Rddh[i] = zkp_range_el_gamal_new(batch_size, PACKING_SIZE, ec);     
    }

    party->in_msg_1 = calloc(num_parties, sizeof(asymoff_presigning_msg_round_1_t));
    party->in_msg_2 = calloc(1, sizeof(asymoff_presigning_msg_round_2_t)); // Only from party 0
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

      for (uint64_t i = 0; i < num_parties; ++i) zkp_range_el_gamal_free(offline->phi_Rddh[i]);
      free(offline->phi_Rddh);
      
      zkp_el_gamal_dlog_free(offline->phi_eph);

      free_scalar_array(offline->Paillier_packed_C, batch_size/PACKING_SIZE);

      free_gr_el_array(offline->A1, batch_size);
      free_gr_el_array(offline->A2, batch_size);
      free_gr_el_array(offline->H, batch_size);
      free_scalar_array(offline->alpha, batch_size);

      free(offline);
 
    } else { // i > 0

      asymoff_presigning_data_online_t *online = party->online;

      for (uint64_t i = 0; i < num_parties; ++i) zkp_range_el_gamal_free(online->phi_Rddh[i]);
      free(online->phi_Rddh);

      free_scalar_array(online->Paillier_packed_K, batch_size/PACKING_SIZE);

      free_scalar_array(online->b, batch_size);
      free_scalar_array(online->k, batch_size);
      free_gr_el_array(online->B1, batch_size);
      free_gr_el_array(online->B2, batch_size);

      free(online);
    }

    free(party->in_msg_1);
    free(party->in_msg_2);  
    free(party);
  }

  free(presign_parties);
}

int asymoff_presigning_execute_round_1(asymoff_presigning_data_t *party) {

  if (party->i == 0) return 1;

  pinfo("Player %ld: Executing Round 1\n", party->i);

  asymoff_presigning_data_online_t *online = party->online;
  uint64_t num_parties = party->num_parties;
  uint64_t batch_size = party->batch_size;

  scalar_t *nu = new_scalar_array(batch_size/PACKING_SIZE);

  scalar_t packed_k = scalar_new();
  
  for (uint64_t l = 0; l < batch_size; ++l) {
  
    scalar_sample_in_range(online->k[l], ec_group_order(party->ec), 0);
    scalar_sample_in_range(online->b[l], ec_group_order(party->ec), 0);

    group_operation(online->B1[l], NULL, party->gen, online->b[l], party->ec);
    group_operation(online->B2[l], NULL, party->gen, online->k[l], party->ec);
    group_operation(online->B2[l], online->B2[l], party->Y, online->b[l], party->ec);
  }

  for (uint64_t packed_l = 0; packed_l < batch_size/PACKING_SIZE; ++packed_l) {
      paillier_encryption_sample(nu[packed_l],party->paillier_pub[party->i]);
      pack_plaintexts(packed_k, &online->k[PACKING_SIZE*packed_l], PACKING_SIZE, party->paillier_pub[party->i]->N, 1);
      paillier_encryption_encrypt(online->Paillier_packed_K[packed_l], packed_k, nu[packed_l], party->paillier_pub[party->i]);
    }

  for (uint64_t j = 0; j < num_parties; ++j) {
    if (j == party->i ) continue;
    
    zkp_range_el_gamal_public_t phi_Rddh_public;
    phi_Rddh_public.batch_size    = party->batch_size;
    phi_Rddh_public.packing_size  = PACKING_SIZE;
    phi_Rddh_public.paillier_pub  = party->paillier_pub[party->i];
    phi_Rddh_public.rped_pub      = party->rped_pub[j];
    phi_Rddh_public.A1  = online->B1;
    phi_Rddh_public.A2  = online->B2;
    phi_Rddh_public.Y   = party->Y;
    phi_Rddh_public.packed_C   = online->Paillier_packed_K;
    phi_Rddh_public.ec   = party->ec;
    phi_Rddh_public.g   = party->gen;

    zkp_range_el_gamal_secret_t phi_Rddh_secret;
    phi_Rddh_secret.b = online->b;
    phi_Rddh_secret.rho = nu; 
    phi_Rddh_secret.x = online->k;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
    zkp_range_el_gamal_prove(online->phi_Rddh[j], &phi_Rddh_secret, &phi_Rddh_public, party->aux);
  }

  free_scalar_array(nu, batch_size/PACKING_SIZE);
  scalar_free(packed_k);

  // TODO: Echo Broadcast B,K?
  // TODO: No Commit/Decommit hash?

  return 0;
}

uint64_t asymoff_presigning_send_msg_1(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i == 0) return 0;

  asymoff_presigning_msg_round_1_t *in_msg_1 = &receiver->in_msg_1[sender->i];
  in_msg_1->B1 = sender->online->B1;
  in_msg_1->B2 = sender->online->B2;
  in_msg_1->Paillier_packed_K = sender->online->Paillier_packed_K;
  in_msg_1->phi_Rddh = sender->online->phi_Rddh[receiver->i];

  return sender->batch_size * (2  + 2 * PAILLIER_MODULUS_BYTES) + zkp_range_el_gamal_proof_bytelen(sender->batch_size, PACKING_SIZE);
}

int asymoff_presigning_execute_round_2(asymoff_presigning_data_t *party) {
  pinfo("Player %ld: Executing Round 2\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t batch_size  = party->batch_size;

  asymoff_presigning_msg_round_1_t *in_msg_1;

  for (uint64_t j = 1; j < num_parties; ++j) {
    if (j == party->i ) continue;
    
    in_msg_1 = &party->in_msg_1[j];

    zkp_range_el_gamal_public_t phi_Rddh_public;
    phi_Rddh_public.batch_size    = party->batch_size;
    phi_Rddh_public.packing_size  = PACKING_SIZE;
    phi_Rddh_public.paillier_pub  = party->paillier_pub[j];
    phi_Rddh_public.rped_pub      = party->rped_pub[party->i];
    phi_Rddh_public.A1  = in_msg_1->B1;
    phi_Rddh_public.A2  = in_msg_1->B2;
    phi_Rddh_public.Y   = party->Y;
    phi_Rddh_public.packed_C   = in_msg_1->Paillier_packed_K;
    phi_Rddh_public.ec   = party->ec;
    phi_Rddh_public.g   = party->gen;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));
    if (zkp_range_el_gamal_verify(in_msg_1->phi_Rddh, &phi_Rddh_public, party->aux) != 1) {
      printf("ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", j);
      return 1;
    }
  }

  if (party->i != 0) return 0;

  asymoff_presigning_data_offline_t *offline = party->offline;

  scalar_t *lambda = new_scalar_array(batch_size);
  scalar_t *rho    = new_scalar_array(batch_size/PACKING_SIZE);
  scalar_t temp    = scalar_new();
  
  for (uint64_t l = 0; l < batch_size; ++l) {

    scalar_sample_in_range(offline->alpha[l], ec_group_order(party->ec), 0);
    scalar_sample_in_range(lambda[l], ec_group_order(party->ec), 0);

    scalar_inv(temp, offline->alpha[l], ec_group_order(party->ec));
    group_operation(offline->H[l], NULL, party->gen, temp, party->ec);

    group_operation(offline->A1[l], NULL, party->gen, lambda[l], party->ec);

    group_operation(offline->A2[l], NULL, party->gen, offline->alpha[l], party->ec);
    group_operation(offline->A2[l], offline->A2[l], party->Y, lambda[l], party->ec);
  }

  for (uint64_t packed_l = 0; packed_l < batch_size/PACKING_SIZE; ++packed_l) {

    pack_plaintexts(temp, &offline->alpha[PACKING_SIZE*packed_l], PACKING_SIZE, party->paillier_pub[party->i]->N, 1);
    paillier_encryption_sample(rho[packed_l], party->paillier_pub[party->i]);
    paillier_encryption_encrypt(offline->Paillier_packed_C[packed_l], temp, rho[packed_l], party->paillier_pub[party->i]);
  }

  zkp_el_gamal_dlog_public_t phi_eph_public;
  phi_eph_public.batch_size = batch_size;
  phi_eph_public.B1 = offline->A1;
  phi_eph_public.B2 = offline->A2;
  phi_eph_public.H  = calloc(batch_size, sizeof(gr_elem_t));
  phi_eph_public.R  = offline->H;
  phi_eph_public.ec  = party->ec;
  phi_eph_public.g  = party->gen;
  phi_eph_public.Y  = party->Y;

  for (uint64_t l = 0; l < batch_size; ++l) phi_eph_public.H[l] = party->gen;

  zkp_el_gamal_dlog_secret_t phi_eph_secret;
  phi_eph_secret.lambda = new_scalar_array(batch_size);
  phi_eph_secret.rho    = new_scalar_array(batch_size);
  phi_eph_secret.k      = offline->alpha;
  phi_eph_secret.b      = lambda;
  
  zkp_el_gamal_dlog_anchor(offline->phi_eph, &phi_eph_secret, &phi_eph_public);
    
  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
  zkp_el_gamal_dlog_prove(offline->phi_eph, &phi_eph_secret, &phi_eph_public, party->aux, 1);

  free(phi_eph_public.H);
  free_scalar_array(phi_eph_secret.lambda, batch_size);
  free_scalar_array(phi_eph_secret.rho, batch_size);

  for (uint64_t j = 1; j < num_parties; ++j) {
    
    zkp_range_el_gamal_public_t phi_Rddh_public;
    phi_Rddh_public.batch_size    = party->batch_size;
    phi_Rddh_public.packing_size  = PACKING_SIZE;
    phi_Rddh_public.paillier_pub  = party->paillier_pub[party->i];
    phi_Rddh_public.rped_pub      = party->rped_pub[j];
    phi_Rddh_public.A1  = offline->A1;
    phi_Rddh_public.A2  = offline->A2;
    phi_Rddh_public.Y   = party->Y;
    phi_Rddh_public.packed_C   = offline->Paillier_packed_C;
    phi_Rddh_public.ec   = party->ec;
    phi_Rddh_public.g   = party->gen;

    zkp_range_el_gamal_secret_t phi_Rddh_secret;
    phi_Rddh_secret.b = lambda;
    phi_Rddh_secret.rho = rho; 
    phi_Rddh_secret.x = offline->alpha;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
    zkp_range_el_gamal_prove(offline->phi_Rddh[j], &phi_Rddh_secret, &phi_Rddh_public, party->aux);
  }

  free_scalar_array(lambda, batch_size);
  free_scalar_array(rho, batch_size/PACKING_SIZE);
  scalar_free(temp);

  return 0;
}

uint64_t asymoff_presigning_send_msg_2(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i != 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_msg_round_2_t *in_msg_2 = &receiver->in_msg_2[sender->i];
  asymoff_presigning_data_offline_t *offline = sender->offline;

  in_msg_2->A1        = offline->A1;
  in_msg_2->A2        = offline->A2;
  in_msg_2->packed_C  = offline->Paillier_packed_C;
  in_msg_2->H         = offline->H;
  in_msg_2->phi_eph   = offline->phi_eph;
  in_msg_2->phi_Rddh  = offline->phi_Rddh[receiver->i];

  return sender->batch_size * (3 * GROUP_ELEMENT_BYTES + 2 * PAILLIER_MODULUS_BYTES) + zkp_el_gamal_dlog_proof_bytelen(sender->batch_size, 1) + zkp_range_el_gamal_proof_bytelen(sender->batch_size, PACKING_SIZE);
}

int asymoff_presigning_execute_final(asymoff_presigning_data_t *party) {
  pinfo("Player %ld: Executing Finalizationization\n", party->i);
  if (party->i ==0) return 0;
  
  uint64_t batch_size = party->batch_size;

  asymoff_presigning_msg_round_2_t *in_msg_2 = &party->in_msg_2[0];

  zkp_el_gamal_dlog_public_t phi_eph_public;
  phi_eph_public.batch_size = batch_size;
  phi_eph_public.B1 = in_msg_2->A1;
  phi_eph_public.B2 = in_msg_2->A2;
  phi_eph_public.H  = calloc(batch_size, sizeof(gr_elem_t));
  phi_eph_public.R  = in_msg_2->H;
  phi_eph_public.ec  = party->ec;
  phi_eph_public.g  = party->gen;
  phi_eph_public.Y  = party->Y;

  for (uint64_t l = 0; l < batch_size; ++l) phi_eph_public.H[l] = party->gen;
    
  uint64_t party_0_i = 0;
  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party_0_i, sizeof(uint64_t));
  int res = zkp_el_gamal_dlog_verify(in_msg_2->phi_eph, &phi_eph_public, party->aux, 1);

  free(phi_eph_public.H);

  if (res != 1) {
    printf("ZKP Ephemeral El Gamal DLog verification failed. Received from party %ld\n", party_0_i);
    return 1;
  }

  zkp_range_el_gamal_public_t phi_Rddh_public;
  phi_Rddh_public.batch_size    = party->batch_size;
  phi_Rddh_public.packing_size  = PACKING_SIZE;
  phi_Rddh_public.paillier_pub  = party->paillier_pub[party_0_i];
  phi_Rddh_public.rped_pub      = party->rped_pub[party->i];
  phi_Rddh_public.A1  = in_msg_2->A1;
  phi_Rddh_public.A2  = in_msg_2->A2;
  phi_Rddh_public.Y   = party->Y;
  phi_Rddh_public.packed_C   = in_msg_2->packed_C;
  phi_Rddh_public.ec   = party->ec;
  phi_Rddh_public.g   = party->gen;

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party_0_i, sizeof(uint64_t));
  if (zkp_range_el_gamal_verify(in_msg_2->phi_Rddh, &phi_Rddh_public, party->aux) != 1)
  {
    printf("ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", party_0_i);
    return 1;
  }

  return 0;
}

void asymoff_presigning_export_data(asymoff_party_data_t **parties, asymoff_presigning_data_t ** const presign_parties) {
  pinfo("Exporting Presigning Data\n");

  uint64_t num_parties = presign_parties[0]->num_parties;
  uint64_t batch_size  = presign_parties[0]->batch_size;
  ec_group_t ec        = presign_parties[0]->ec;
  
  for (uint64_t i = 0; i < num_parties; ++i) {
    parties[i]->batch_size = batch_size;
    parties[i]->next_index = 0;
    
    asymoff_presigning_msg_round_1_t *in_msg_1 = presign_parties[i]->in_msg_1;
      
    // For copy conviniene
    if (i != 0) {
      in_msg_1[i].B1 = presign_parties[i]->online->B1;
      in_msg_1[i].B2 = presign_parties[i]->online->B2;
    }

    gr_elem_t curr_B1;
    gr_elem_t curr_B2;

    for (uint64_t l = 0; l < batch_size; ++l) {
      curr_B1 = parties[i]->joint_B1[l];
      curr_B2 = parties[i]->joint_B2[l];

      group_operation(curr_B1, NULL, NULL, NULL, ec);
      group_operation(curr_B2, NULL, NULL, NULL, ec);

      for (uint64_t j = 1; j < num_parties; ++j) {

        group_operation(curr_B1, curr_B1, in_msg_1[j].B1[l], NULL, ec);
        group_operation(curr_B2, curr_B2, in_msg_1[j].B2[l], NULL, ec);
      }
    }

    if (i == 0 ) {

      asymoff_presigning_data_offline_t *offline = presign_parties[i]->offline; 

      copy_scalar_array(parties[i]->nonce, offline->alpha, batch_size);
      copy_gr_el_array(parties[i]->H, offline->H, batch_size);

    } else { // i > 0
      asymoff_presigning_msg_round_2_t *in_msg_2 = presign_parties[i]->in_msg_2;

      copy_scalar_array(parties[i]->b, presign_parties[i]->online->b, batch_size);
      copy_scalar_array(parties[i]->nonce, presign_parties[i]->online->k, batch_size);
      copy_gr_el_array(parties[i]->H, in_msg_2[0].H, batch_size);

      for (uint64_t l = 0; l < batch_size; ++l) {
        for (uint64_t j = 1; j < num_parties; ++j) {
        group_elem_copy(parties[i]->B1[j][l], in_msg_1[j].B1[l]);
        group_elem_copy(parties[i]->B2[j][l], in_msg_1[j].B2[l]);
        }
      }
    }
  }
}
