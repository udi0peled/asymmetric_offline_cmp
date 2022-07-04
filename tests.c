#include <inttypes.h>
#include <stdio.h>
#include <openssl/rand.h> 

#include "common.h"
#include "algebraic_elements.h"
#include "asymoff_key_generation.h"

struct stam {
  uint8_t b[12];
};

typedef struct stam stam;

uint64_t ret_sizeof(stam *p) {
  return sizeof(p->b);
}

#define NUM_PARTIES 2

int with_info_print = 1;

void send_msg_to_all_others(asymoff_key_gen_data_t **parties, uint64_t sender_i, void (*send_func)(asymoff_key_gen_data_t*, asymoff_key_gen_data_t*)) {
  for (uint64_t j = 0; j < parties[sender_i]->num_parties; ++j) {
    if (sender_i == j) continue;
    send_func(parties[sender_i], parties[j]);
  }
}


int main() {

  ec_group_t ec = ec_group_new();

  scalar_t private_keys[NUM_PARTIES];

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    private_keys[i] = scalar_new();
    scalar_sample_in_range(private_keys[i], ec_group_order(ec) , 0);
  }

  hash_chunk sid;
  RAND_bytes(sid, sizeof(hash_chunk));
  printHexBytes("sid: ", sid, sizeof(hash_chunk), "\n", 0);

  asymoff_key_gen_data_t **parties = asymoff_key_gen_parties_new(private_keys, NUM_PARTIES, sid, ec, ec_group_generator(ec));

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_1(parties[i]);
    send_msg_to_all_others(parties, i, asymoff_key_gen_send_msg_1);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_2(parties[i]);
    send_msg_to_all_others(parties, i, asymoff_key_gen_send_msg_2);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_3(parties[i]);
    send_msg_to_all_others(parties, i, asymoff_key_gen_send_msg_3);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_round_4(parties[i]);
    send_msg_to_all_others(parties, i, asymoff_key_gen_send_msg_4);
  }

  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    asymoff_key_gen_compute_output(parties[i]);
  }


  asymoff_key_gen_parties_free(parties, NUM_PARTIES);
  for (uint64_t i = 0; i < NUM_PARTIES; ++i) {
    scalar_free(private_keys[i]);
  }
  ec_group_free(ec);
}