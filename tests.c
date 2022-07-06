#include <inttypes.h>
#include <stdio.h>
#include <openssl/rand.h> 

#include "asymoff_protocol.h"

struct stam {
  uint8_t b[12];
};

typedef struct stam stam;

uint64_t ret_sizeof(stam *p) {
  return sizeof(p->b);
}

#define NUM_PARTIES 3

int with_info_print = 1;

void key_gen_protocol_execute(asymoff_party_data_t **parties) {

  uint64_t num_parties = parties[0]->num_parties;
  ec_group_t ec = parties[0]->ec;

  scalar_t *private_keys = calloc(num_parties, sizeof(scalar_t));

  for (uint64_t i = 0; i < num_parties; ++i) {
    private_keys[i] = scalar_new();
    scalar_sample_in_range(private_keys[i], ec_group_order(ec) , 0);
  }

  hash_chunk sid;
  RAND_bytes(sid, sizeof(hash_chunk));
  printHexBytes("sid: ", sid, sizeof(hash_chunk), "\n", 0);

  asymoff_key_gen_data_t **kgd_parties = asymoff_key_gen_parties_new(private_keys, num_parties, sid, ec, ec_group_generator(ec));

  for (uint64_t i = 0; i < num_parties; ++i) {
    asymoff_key_gen_compute_round_1(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, asymoff_key_gen_send_msg_1);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {
    asymoff_key_gen_compute_round_2(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, asymoff_key_gen_send_msg_2);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {
    asymoff_key_gen_compute_round_3(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, asymoff_key_gen_send_msg_3);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {
    asymoff_key_gen_compute_round_4(kgd_parties[i]);
    asymoff_key_gen_send_msg_to_all_others(kgd_parties, i, asymoff_key_gen_send_msg_4);
  }

  for (uint64_t i = 0; i < num_parties; ++i) {
    asymoff_key_gen_compute_output(kgd_parties[i]);
  }
  
  asymoff_save_data_from_key_gen(parties, kgd_parties);

  asymoff_key_gen_parties_free(kgd_parties);
  for (uint64_t i = 0; i < num_parties; ++i) {
    scalar_free(private_keys[i]);
  }
  free(private_keys);
}

int main() {
  asymoff_party_data_t **parties = asymoff_protocol_parties_new(NUM_PARTIES);
  key_gen_protocol_execute(parties);
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