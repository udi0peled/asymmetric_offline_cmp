#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h> 

#include "common.h"
#include "asymoff_protocol.h"
#include "asymoff_key_generation.h"
#include "asymoff_presigning.h"
#include "asymoff_signing_cmp.h"
#include "asymoff_signing_aggregate.h"

#define NUM_PARTIES 2

/*************
 *  Helpers  *
 *************/

int with_info_print = 1;
int with_measurements = 0;

uint64_t sent_bytelen[5][NUM_PARTIES][NUM_PARTIES];

struct timespec time_st;
clock_t start_time, end_time;
double exec_time[5][NUM_PARTIES];


void start_timer() {
  if (with_measurements) {
    start_time = clock();
  } else {
    start_time = 0;
  }
}

double get_time() {
  if (with_measurements) {
    end_time = clock();
    return ((double)(end_time-start_time)) /CLOCKS_PER_SEC;
  }
  return 0;
}

void print_measurements(uint64_t rounds){
  if (!with_measurements) return;

  for (uint64_t r = 0; r < rounds; ++r) {
    printf("\n");
    for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
      for (uint64_t j = 0; j < NUM_PARTIES; ++j) {
        if (i == j) continue;
        printf("Round %ld, Party %ld to Party %ld, Bytes Sent: %ld\n", r+1, i, j, sent_bytelen[r][i][j]);
      }
    } 
  }

  for (uint64_t r = 0; r <= rounds; ++r) {
    printf("\n");
    for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
      printf("Round %ld, Party %ld, Time: %f\n", r, i, exec_time[r][i]);
    } 
  }

}

/*************
 *  Key Gen  *
 *************/

void asymoff_key_gen_send_msg_to_all_others(asymoff_key_gen_data_t **kgd_parties, uint64_t sender_i, int round) {

  uint64_t (*send_func)(asymoff_key_gen_data_t*, asymoff_key_gen_data_t*);

  switch (round) {
    case 1: send_func = asymoff_key_gen_send_msg_1; break;
    case 2: send_func = asymoff_key_gen_send_msg_2; break;
    case 3: send_func = asymoff_key_gen_send_msg_3; break;
    case 4: send_func = asymoff_key_gen_send_msg_4; break;
    default: return;
  }

  for (uint64_t j = 0; j < kgd_parties[sender_i]->num_parties; ++j) {
    if (sender_i == j) continue;
    sent_bytelen[round-1][sender_i][j] = send_func(kgd_parties[sender_i], kgd_parties[j]);
  }
}

void key_gen_protocol_execute(asymoff_party_data_t **parties) {
  
  printf("\n____ Key Generation _____\n");

  asymoff_key_gen_data_t **kgd_parties = asymoff_key_gen_parties_new(parties);

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_execute_round_1(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 1);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_execute_round_2(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 2);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_execute_round_3(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 3);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_execute_round_4(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 4);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_execute_final(kgd_parties[i]);
  }

  asymoff_key_gen_export_data(parties, kgd_parties);

  asymoff_key_gen_parties_free(kgd_parties);
}

void key_gen_protocol_mock_execute(asymoff_party_data_t **parties) {
    printf("Key Generation - Mock\n");
    asymoff_key_gen_mock_export_data(parties);
}

void print_after_keygen(asymoff_party_data_t **parties) {

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    printf("Party %ld data after key-gen:\n", i);
    printHexBytes("srid: ", parties[i]->srid, sizeof(hash_chunk), "\n", 0);
    printBIGNUM("x: ", parties[i]->x, "\n");
    for (uint64_t j = 0; j < NUM_PARTIES; ++j) printECPOINT("X[]: ", parties[i]->X[j], parties[i]->ec, "\n", 0);
    for (uint64_t j = 0; j < NUM_PARTIES; ++j) printBIGNUM("Paillier_N[]: ", parties[i]->paillier_pub[j]->N, "\n");
    for (uint64_t j = 0; j < NUM_PARTIES; ++j) printBIGNUM("Pedersen_N[]: ", parties[i]->rped_pub[j]->N, "\n");

    printECPOINT("Y: ", parties[i]->Y, parties[i]->ec, "\n", 0);
    if (i != 0) printBIGNUM("W_0: ", parties[i]->W_0, "\n");
  }
}

/****************
 *  Presigning  *
 ****************/

void asymoff_presigning_send_msg_to_all_others(asymoff_presigning_data_t **presign_parties, uint64_t sender_i, int round) {

  uint64_t (*send_func)(asymoff_presigning_data_t*, asymoff_presigning_data_t*);

  switch (round) {
    case 1: send_func = asymoff_presigning_send_msg_1; break;
    case 2: send_func = asymoff_presigning_send_msg_2; break;
    default: return;
  }
  
  for (uint64_t j = 0; j < presign_parties[sender_i]->num_parties; ++j) {
    if (sender_i == j) continue;
    sent_bytelen[round-1][sender_i][j] = send_func(presign_parties[sender_i], presign_parties[j]);
  }
}

void presigning_execute(asymoff_party_data_t **parties, uint64_t batch_size) {
  
  printf("\n_____ Presigning %ld batch _____\n", batch_size);

  asymoff_presigning_data_t **presign_parties =  asymoff_presigning_parties_new(parties, batch_size);

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_execute_round_1(presign_parties[i]);
    exec_time[0][i] = get_time();
    asymoff_presigning_send_msg_to_all_others(presign_parties, i, 1);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_execute_round_2(presign_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_presigning_send_msg_to_all_others(presign_parties, i, 2);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_execute_final(presign_parties[i]);
    exec_time[2][i] = get_time();
  }
  
  asymoff_presigning_export_data(parties, presign_parties);
  
  asymoff_presigning_parties_free(presign_parties);
}

void print_after_presigning(asymoff_party_data_t **parties, uint64_t num_print) {

  printf("Data After Pre-Signing\n");

  asymoff_party_data_t *party;
  ec_group_t ec = parties[0]->ec;

  for (uint64_t l = 0; l < num_print; ++l) {
    party = parties[0];
    printECPOINT("B1_0 = ", party->B1[l][0], ec, "\n", 1);
    printECPOINT("B2_0 = ", party->B2[l][0], ec, "\n", 1);

    for (uint64_t i = 1; i < NUM_PARTIES; ++i) {

      party = parties[i];

      for (uint64_t j = 1; j < NUM_PARTIES; ++j) {

        printf("B1_%ld_%ld = ", i, j);
        printECPOINT("", party->B1[j][l], ec, "\n", 1);

        printf("B2_%ld_%ld = ", i, j);
        printECPOINT("", party->B2[j][l], ec, "\n", 1);
      }
    }
  }
}


/*****************
 *  Signing CMP  *
 *****************/

void asymoff_signing_cmp_send_msg_to_all_others(asymoff_sign_cmp_data_t **cmp_parties, uint64_t sender_i, int round) {

  uint64_t (*send_func)(asymoff_sign_cmp_data_t*, asymoff_sign_cmp_data_t*);

  switch (round) {
    case 1: send_func = asymoff_signing_cmp_send_msg_1; break;
    case 2: send_func = asymoff_signing_cmp_send_msg_2; break;
    case 3: send_func = asymoff_signing_cmp_send_msg_3; break;
    default: return;
  }
  
  for (uint64_t j = 1; j < cmp_parties[sender_i]->num_parties; ++j) {
    if (sender_i == j) continue;
    sent_bytelen[round-1][sender_i][j] = send_func(cmp_parties[sender_i], cmp_parties[j]);
  }
}

void signing_cmp_execute(asymoff_party_data_t **parties, uint64_t num_sigs) {

  printf("\n_____ Signing CMP %ld msgs ______\n", num_sigs);

  asymoff_sign_cmp_data_t **cmp_parties = asymoff_signing_cmp_parties_new(parties, num_sigs);
  
  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_cmp_execute_round_1(cmp_parties[i]);
    exec_time[0][i] = get_time();
    asymoff_signing_cmp_send_msg_to_all_others(cmp_parties, i, 1);
  }

  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_cmp_execute_round_2(cmp_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_signing_cmp_send_msg_to_all_others(cmp_parties, i, 2);
  }

  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_cmp_execute_round_3(cmp_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_signing_cmp_send_msg_to_all_others(cmp_parties, i, 3);
  }

  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_cmp_execute_final(cmp_parties[i]);
    exec_time[1][i] = get_time();
  }

  asymoff_signing_cmp_export_data(parties, cmp_parties);

  asymoff_signing_cmp_parties_free(cmp_parties);
}

void signing_cmp_mock_execute(asymoff_party_data_t **parties, uint64_t num_sigs) {
    printf("\n_____ Signing CMP %ld msgs - Mock _____\n", num_sigs);
  
    for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
      
      parties[i]->num_sigs = num_sigs;
      parties[i]->curr_index = parties[i]->next_index;
      parties[i]->next_index = parties[i]->curr_index + num_sigs;

      if (parties[i]->next_index > parties[i]->batch_size)
      {
        printf("Party %ld can't sign %ld signature. Batch size: %ld, next index: %ld.\n", num_sigs, i, parties[i]->batch_size, parties[i]->next_index); 
        return;
      }
    }

    asymoff_signing_cmp_execute_mock_export_data(parties);
}

void print_signing_cmp_ouput(asymoff_party_data_t ** const parties, uint64_t num_sigs){
  
  asymoff_party_data_t *party;
  ec_group_t ec = parties[0]->ec;

  for (uint64_t l = 0; l < num_sigs; ++l) {
    for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
      party = parties[i];

      if (l == 0)  {
        printf("x_%ld = ", i);
        printBIGNUM("", party->x, "\n");
      }

      printf("H_%ld_%ld = ", l, i);
      printECPOINT("", party->H[l], ec, "\n", 1);

      printf("R_%ld_%ld = ", l, i);
      printECPOINT("", party->R[l], ec, "\n", 1);

      printf("k_%ld_%ld = ", l, i);
      printBIGNUM("", party->nonce[l], "\n");

      printf("chi_%ld_%ld = ", l, i);
      printBIGNUM("", party->chi[l], "\n");
    }
  }
}

/************************
 *  Signing Aggregation *
 ************************/


void asymoff_signing_aggregate_send_msg_to_all_others(asymoff_sign_agg_data_t **signing_parties, uint64_t sender_i, int round) {

  uint64_t (*send_func)(asymoff_sign_agg_data_t*, asymoff_sign_agg_data_t*);

  switch (round) {
    case 1: send_func = asymoff_signing_aggregate_send_msg_1; break;
    case 2: send_func = asymoff_signing_aggregate_send_msg_2; break;
    case 3: send_func = asymoff_signing_aggregate_send_msg_3; break;
    case 4: {
      sent_bytelen[round-1][sender_i][0] = asymoff_signing_aggregate_send_msg_offline(signing_parties[sender_i], signing_parties[0]);
      return;
    }

    default: return;
  }
  
  for (uint64_t j = 1; j < signing_parties[sender_i]->num_parties; ++j) {
    if (sender_i == j) continue;
    sent_bytelen[round-1][sender_i][j] = send_func(signing_parties[sender_i], signing_parties[j]);
  }
}

void signing_aggregate_execute(asymoff_party_data_t **parties, uint64_t num_msgs) {
  printf("\n_____ Signing Aggregate %ld msgs _____\n", num_msgs);

  scalar_t *msgs = new_scalar_array(num_msgs);
  for (uint64_t l = 0; l < num_msgs; ++l) scalar_sample_in_range(msgs[l], ec_group_order(parties[0]->ec), 0);

  asymoff_sign_agg_data_t **signing_parties = asymoff_signing_aggregate_parties_new(parties, msgs);
  
  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_aggregate_execute_round_1(signing_parties[i]);
    exec_time[0][i] = get_time();
    asymoff_signing_aggregate_send_msg_to_all_others(signing_parties, i, 1);
  }

  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_aggregate_execute_round_2(signing_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_signing_aggregate_send_msg_to_all_others(signing_parties, i, 2);
  }

  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_aggregate_execute_round_3(signing_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_signing_aggregate_send_msg_to_all_others(signing_parties, i, 3);
  }
  
  for (uint64_t i = 1; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_signing_aggregate_execute_final(signing_parties[i]);
    exec_time[1][i] = get_time();
  }

  asymoff_signing_aggregate_send_msg_to_all_others(signing_parties, 1, 4);

  scalar_t *sigs = new_scalar_array(num_msgs);

  assert(asymoff_signing_aggregate_execute_offline(signing_parties[0], sigs) == 0);

  printf("\n_____ All messages signed succesfully! _____\n\n");

  free_scalar_array(msgs, num_msgs);
  free_scalar_array(sigs, num_msgs);

  asymoff_signing_aggregate_parties_free(signing_parties);
}

int main(int argc, char *argv[]) {

  uint64_t batch_size = 3;
  if (argc >= 2) sscanf(argv[1], "%ld", &batch_size);
  batch_size = PACKING_SIZE*((batch_size+PACKING_SIZE-1)/PACKING_SIZE);

  with_measurements = 0;
  with_info_print = 1;

  asymoff_party_data_t **parties = asymoff_protocol_parties_new(NUM_PARTIES);
  asymoff_protocol_parties_set(parties, NULL, NULL);

  key_gen_protocol_execute(parties);
  //key_gen_protocol_mock_execute(parties);
  
  //print_after_keygen(parties);

  asymoff_protocol_parties_new_batch(parties, batch_size);

  presigning_execute(parties, batch_size);

  print_measurements(2);

  //print_after_presigning(parties, 1);

  signing_cmp_execute(parties, batch_size);

  //signing_cmp_mock_execute(parties, batch_size);

  print_measurements(4);

  //print_signing_cmp_ouput(parties, 1);

  signing_aggregate_execute(parties, batch_size);

  print_measurements(4);

  asymoff_protocol_parties_free_batch(parties);
  asymoff_protocol_parties_free(parties);
}