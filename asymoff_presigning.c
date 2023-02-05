#include "asymoff_presigning.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

ENABLE_TIME(presign)

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
    party->Y = parties[i]->Y;
    
    party->paillier_pub = parties[i]->paillier_pub;
    party->rped_pub = parties[i]->rped_pub;

    if (i == 0) {

      party->offline = malloc(sizeof(asymoff_presigning_data_offline_t));

      asymoff_presigning_data_offline_t *offline = party->offline;

      offline->H     = gr_el_array_new(batch_size, ec);
      offline->alpha = scalar_array_new(batch_size);

      offline->Paillier_packed_C = scalar_array_new(batch_size/PACKING_SIZE);

      offline->phi_Rddh = calloc(num_parties, sizeof(zkp_range_el_gamal_proof_t*));
      for (uint64_t i = 0; i < num_parties; ++i) offline->phi_Rddh[i] = zkp_range_el_gamal_new(batch_size, PACKING_SIZE, ec);
      

    } else { // i > 0

      party->online = malloc(sizeof(asymoff_presigning_data_online_t));

      asymoff_presigning_data_online_t *online = party->online;

      online->B1 = gr_el_array_new(batch_size, ec);
      online->B2 = gr_el_array_new(batch_size, ec);
      online->k  = scalar_array_new(batch_size);
      online->b  = scalar_array_new(batch_size);

      online->Paillier_packed_K = scalar_array_new(batch_size/PACKING_SIZE);
      online->nu = scalar_array_new(batch_size/PACKING_SIZE);

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
      
      scalar_array_free(offline->Paillier_packed_C, batch_size/PACKING_SIZE);

      gr_el_array_free(offline->H, batch_size);
      scalar_array_free(offline->alpha, batch_size);

      free(offline);
 
    } else { // i > 0

      asymoff_presigning_data_online_t *online = party->online;

      for (uint64_t i = 0; i < num_parties; ++i) zkp_range_el_gamal_free(online->phi_Rddh[i]);
      free(online->phi_Rddh);

      scalar_array_free(online->Paillier_packed_K, batch_size/PACKING_SIZE);
      scalar_array_free(online->nu, batch_size/PACKING_SIZE);

      scalar_array_free(online->b, batch_size);
      scalar_array_free(online->k, batch_size);
      gr_el_array_free(online->B1, batch_size);
      gr_el_array_free(online->B2, batch_size);

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
  uint64_t packed_len = batch_size/PACKING_SIZE;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  ec_group_t ec = party->ec;

  scalar_t packed_k = scalar_new();
  
  for (uint64_t l = 0; l < batch_size; ++l) {
  
    scalar_sample_in_range(online->k[l], ec_group_order(party->ec), 0, bn_ctx);
    scalar_sample_in_range(online->b[l], ec_group_order(party->ec), 0, bn_ctx);

    group_operation(online->B1[l], NULL, online->b[l], NULL, NULL, ec, bn_ctx);
    group_operation(online->B2[l], NULL, online->k[l], party->Y, online->b[l], ec, bn_ctx);
  }

  start_timer();
  for (uint64_t packed_l = 0, l = 0; packed_l < packed_len; ++packed_l, l += PACKING_SIZE) {
    //paillier_encryption_sample(online->nu[packed_l],party->paillier_pub[party->i]);
    BN_rand_range(online->nu[packed_l], party->paillier_pub[party->i]->N);
    pack_plaintexts(packed_k, &online->k[l], PACKING_SIZE, party->paillier_pub[party->i]->N, 1);
    paillier_encryption_encrypt(online->Paillier_packed_K[packed_l], packed_k, online->nu[packed_l], party->paillier_pub[party->i]);
  }
  get_time("paillier packed:	");

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

    zkp_range_el_gamal_secret_t phi_Rddh_secret;
    phi_Rddh_secret.b = online->b;
    phi_Rddh_secret.rho = online->nu; 
    phi_Rddh_secret.x = online->k;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));
    start_timer();
    zkp_range_el_gamal_prove(online->phi_Rddh[j], &phi_Rddh_secret, &phi_Rddh_public, party->aux);
    get_time("zkp_range_el_gamal_prove:	");
  }

  scalar_free(packed_k);
  BN_CTX_free(bn_ctx);

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

  return sender->batch_size*2*GROUP_ELEMENT_BYTES  + 2*(sender->batch_size/PACKING_SIZE)*PAILLIER_MODULUS_BYTES + zkp_range_el_gamal_proof_bytelen(sender->batch_size, PACKING_SIZE);
}

int asymoff_presigning_execute_round_2(asymoff_presigning_data_t *party) {
  pinfo("Player %ld: Executing Round 2\n", party->i);

  uint64_t num_parties = party->num_parties;
  uint64_t batch_size  = party->batch_size;
  uint64_t packed_len = batch_size/PACKING_SIZE;

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

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &j, sizeof(uint64_t));
    start_timer();
    if (zkp_range_el_gamal_verify(in_msg_1->phi_Rddh, &phi_Rddh_public, party->aux) != 1) {
      printf("ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", j);
      return 1;
    }
    get_time("zkp_range_el_gamal_verify:	");
  }

  if (party->i != 0) return 0;

  asymoff_presigning_data_offline_t *offline = party->offline;

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  scalar_t *rho    = scalar_array_new(packed_len);
  scalar_t temp    = scalar_new();
  
  for (uint64_t l = 0; l < batch_size; ++l) {
    scalar_sample_in_range(offline->alpha[l], ec_group_order(party->ec), 0, bn_ctx);
    group_operation(offline->H[l], NULL, NULL, ec_group_generator(party->ec), offline->alpha[l], party->ec, bn_ctx);
  }
  for (uint64_t packed_l = 0, l = 0; packed_l < packed_len; ++packed_l, l += PACKING_SIZE) {

    pack_plaintexts(temp, &offline->alpha[l], PACKING_SIZE, party->paillier_pub[party->i]->N, 1);
    paillier_encryption_sample(rho[packed_l], party->paillier_pub[party->i]);
    paillier_encryption_encrypt(offline->Paillier_packed_C[packed_l], temp, rho[packed_l], party->paillier_pub[party->i]);
  }

  gr_elem_t unit_el = group_elem_new(party->ec);
  scalar_t zero_scalar = scalar_new();

  group_operation(unit_el, NULL, NULL, NULL, NULL, party->ec, bn_ctx);
  scalar_set_ul(zero_scalar, 0);

  gr_elem_t *unit_el_arr = calloc(batch_size, sizeof(gr_elem_t));
  scalar_t *zero_scalar_arr = calloc(batch_size, sizeof(scalar_t));

  for (uint64_t l = 0; l < batch_size; ++l) {
    unit_el_arr[l] = unit_el;
    zero_scalar_arr[l] = zero_scalar;
  }
  
  for (uint64_t j = 1; j < num_parties; ++j) {
    
    zkp_range_el_gamal_public_t phi_Rddh_public;
    phi_Rddh_public.batch_size    = party->batch_size;
    phi_Rddh_public.packing_size  = PACKING_SIZE;
    phi_Rddh_public.paillier_pub  = party->paillier_pub[party->i];
    phi_Rddh_public.rped_pub      = party->rped_pub[j];
    phi_Rddh_public.A1  = unit_el_arr;
    phi_Rddh_public.A2  = offline->H;
    phi_Rddh_public.Y   = party->Y;
    phi_Rddh_public.packed_C   = offline->Paillier_packed_C;
    phi_Rddh_public.ec   = party->ec;

    zkp_range_el_gamal_secret_t phi_Rddh_secret;
    phi_Rddh_secret.b = zero_scalar_arr;
    phi_Rddh_secret.rho = rho; 
    phi_Rddh_secret.x = offline->alpha;

    zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party->i, sizeof(uint64_t));

    start_timer();
    zkp_range_el_gamal_prove(offline->phi_Rddh[j], &phi_Rddh_secret, &phi_Rddh_public, party->aux);
    get_time("zkp_range_el_gamal_prove:	");
  }

  scalar_array_free(rho, packed_len);
  scalar_free(temp);
  scalar_free(zero_scalar);
  group_elem_free(unit_el);
  free(unit_el_arr);
  free(zero_scalar_arr);
  BN_CTX_free(bn_ctx);

  return 0;
}

uint64_t asymoff_presigning_send_msg_2(asymoff_presigning_data_t *sender, asymoff_presigning_data_t *receiver) {
  if (sender->i != 0) return 0;
  if (receiver->i == 0) return 0;

  asymoff_presigning_msg_round_2_t *in_msg_2 = &receiver->in_msg_2[sender->i];
  asymoff_presigning_data_offline_t *offline = sender->offline;

  in_msg_2->packed_C  = offline->Paillier_packed_C;
  in_msg_2->H         = offline->H;
  in_msg_2->phi_Rddh  = offline->phi_Rddh[receiver->i];

  return sender->batch_size * (3*GROUP_ELEMENT_BYTES + 2*PAILLIER_MODULUS_BYTES) + zkp_el_gamal_dlog_proof_bytelen(sender->batch_size, 1) + zkp_range_el_gamal_proof_bytelen(sender->batch_size, PACKING_SIZE);
}

int asymoff_presigning_execute_final(asymoff_presigning_data_t *party) {
  pinfo("Player %ld: Executing Finalization\n", party->i);
  if (party->i ==0) return 0;
  
  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t batch_size = party->batch_size;

  asymoff_presigning_msg_round_2_t *in_msg_2 = &party->in_msg_2[0];

  uint64_t party_0_i = 0;

  gr_elem_t unit_el = group_elem_new(party->ec);

  group_operation(unit_el, NULL, NULL, NULL, NULL, party->ec, bn_ctx);
  gr_elem_t *unit_el_arr = calloc(batch_size, sizeof(gr_elem_t));

  for (uint64_t l = 0; l < batch_size; ++l) unit_el_arr[l] = unit_el;

  zkp_range_el_gamal_public_t phi_Rddh_public;
  phi_Rddh_public.batch_size    = party->batch_size;
  phi_Rddh_public.packing_size  = PACKING_SIZE;
  phi_Rddh_public.paillier_pub  = party->paillier_pub[party_0_i];
  phi_Rddh_public.rped_pub      = party->rped_pub[party->i];
  phi_Rddh_public.A1  = unit_el_arr;
  phi_Rddh_public.A2  = in_msg_2->H;
  phi_Rddh_public.Y   = party->Y;
  phi_Rddh_public.packed_C   = in_msg_2->packed_C;
  phi_Rddh_public.ec   = party->ec;

  zkp_aux_info_update(party->aux, sizeof(hash_chunk), &party_0_i, sizeof(uint64_t));
  start_timer();
  if (zkp_range_el_gamal_verify(in_msg_2->phi_Rddh, &phi_Rddh_public, party->aux) != 1)
  {
    printf("ZKP Range El Gamal Commitment verification failed. Received from party %ld\n", party_0_i);
    return 1;
  }
  get_time("zkp_range_el_gamal_verify:	");

  BN_CTX_free(bn_ctx);

  return 0;
}

void asymoff_presigning_export_data(asymoff_party_data_t **parties, asymoff_presigning_data_t ** const presign_parties) {

  BN_CTX *bn_ctx = BN_CTX_secure_new();

  uint64_t num_parties = presign_parties[0]->num_parties;
  uint64_t batch_size  = presign_parties[0]->batch_size;
  ec_group_t ec        = presign_parties[0]->ec;
  
  for (uint64_t i = 0; i < num_parties; ++i) {

    parties[i]->batch_size = batch_size;
    parties[i]->next_index = 0;
    parties[i]->curr_index = 0;
    
    asymoff_presigning_msg_round_1_t *in_msg_1 = presign_parties[i]->in_msg_1;

    // For convinience
    if (i!= 0) {
      in_msg_1[i].B1 = presign_parties[i]->online->B1;
      in_msg_1[i].B2 = presign_parties[i]->online->B2;
    }
    
    for (uint64_t l = 0; l < batch_size; ++l) {

      EC_POINT_set_to_infinity(ec, parties[i]->joint_B1[l]);
      EC_POINT_set_to_infinity(ec, parties[i]->joint_B2[l]);

      for (uint64_t j = 1; j < num_parties; ++j) {

        EC_POINT_add(ec, parties[i]->joint_B1[l], parties[i]->joint_B1[l], in_msg_1[j].B1[l], bn_ctx);
        EC_POINT_add(ec, parties[i]->joint_B2[l], parties[i]->joint_B2[l], in_msg_1[j].B2[l], bn_ctx);
      }
    }

    if (i == 0 ) {

      asymoff_presigning_data_offline_t *offline = presign_parties[i]->offline; 
      
      scalar_array_copy(parties[i]->nonce, offline->alpha, batch_size);
      gr_el_array_copy(parties[i]->H, offline->H, batch_size);

    } else { // i > 0
      asymoff_presigning_msg_round_2_t *in_msg_2 = presign_parties[i]->in_msg_2;

      scalar_array_copy(parties[i]->b, presign_parties[i]->online->b, batch_size);
      scalar_array_copy(parties[i]->nonce, presign_parties[i]->online->k, batch_size);
      gr_el_array_copy(parties[i]->H, in_msg_2[0].H, batch_size);
      
      for (uint64_t j = 1; j < num_parties; ++j) {
        gr_el_array_copy(parties[i]->B1[j], presign_parties[i]->in_msg_1[j].B1, batch_size);
        gr_el_array_copy(parties[i]->B2[j], presign_parties[i]->in_msg_1[j].B2, batch_size);
      }
    }
  }

  BN_CTX_free(bn_ctx);

}
