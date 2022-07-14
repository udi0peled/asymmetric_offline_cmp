#include <inttypes.h>
#include <stdio.h>
#include <time.h>
#include <openssl/rand.h> 

#include "asymoff_protocol.h"
#include "asymoff_key_generation.h"
#include "asymoff_presigning.h"

#define NUM_PARTIES 3

int with_info_print = 1;
int with_time_measure = 0;

uint64_t sent_bytelen[5][NUM_PARTIES][NUM_PARTIES];

struct timespec time_st;
clock_t start_time, end_time;
double exec_time[5][NUM_PARTIES];


void start_timer() {
  if (with_time_measure) {
    start_time = clock();
  } else {
    start_time = 0;
  }
}

double get_time() {
  if (with_time_measure) {
    end_time = clock();
    return ((double)(end_time-start_time)) /CLOCKS_PER_SEC;
  }
  return 0;
}

void print_sent_bytelen(uint64_t rounds){
  for (uint64_t r = 0; r < rounds; ++r) {
    printf("\n");
    for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
      for (uint64_t j = 0; j < NUM_PARTIES; ++j) {
        if (i == j) continue;
        printf("Round %ld, Party %ld to Party %ld, Bytes Sent: %ld\n", r+1, i, j, sent_bytelen[r][i][j]);
      }
    } 
  }
}

/**
 *  Key Gen
 */

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
  
  printf("Key Generation\n");

  asymoff_key_gen_data_t **kgd_parties = asymoff_key_gen_parties_new(parties);

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_1(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 1);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_2(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 2);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_3(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 3);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_4(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, 4);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_final(kgd_parties[i]);
  }
  
  print_sent_bytelen(4);

  asymoff_key_gen_export_data(parties, kgd_parties);

  asymoff_key_gen_parties_free(kgd_parties);
}

void key_gen_protocol_mock_execute(asymoff_party_data_t **parties) {
    printf("Key Generation - Mock\n");
    asymoff_key_gen_mock_export_data(parties);
}

/**
 *    Presigning  
 */

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
  
  printf("Presigning\n");

  asymoff_presigning_data_t **presign_parties =  asymoff_presigning_parties_new(parties, batch_size);

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_compute_round_1(presign_parties[i]);
    exec_time[0][i] = get_time();
    asymoff_presigning_send_msg_to_all_others(presign_parties, i, 1);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_compute_round_2(presign_parties[i]);
    exec_time[1][i] = get_time();
    asymoff_presigning_send_msg_to_all_others(presign_parties, i, 2);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    start_timer();
    asymoff_presigning_compute_final(presign_parties[i]);
    exec_time[2][i] = get_time();
  }

  print_sent_bytelen(2);

  for (uint64_t r = 0; r < 3; ++r) {
    printf("\n");
    for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
      printf("Round %ld, Party %ld, Time: %f\n", r, i, exec_time[r][i]);
    } 
  }

  asymoff_protocol_parties_new_batch(parties, batch_size);

  asymoff_presigning_export_data(parties, presign_parties);
  
  asymoff_protocol_parties_free_batch(parties);
  asymoff_presigning_parties_free(presign_parties);
}

int main(int argc, char *argv[]) {

  with_time_measure = 0;

  asymoff_party_data_t **parties = asymoff_protocol_parties_new(NUM_PARTIES);
  asymoff_protocol_parties_set(parties, NULL, NULL);

  key_gen_protocol_execute(parties);
  //key_gen_protocol_mock_execute(parties);
  
  uint64_t batch_size = 1;
  if (argc >= 2) sscanf(argv[1], "%ld", &batch_size);
  printf("batch size = %ld\n", batch_size);
  presigning_execute(parties, batch_size);
  
/*
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
*/

  asymoff_protocol_parties_free(parties);
}