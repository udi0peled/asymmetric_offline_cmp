#include "asymoff_signing_cmp.h"
#include "common.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdarg.h>

int asymoff_signing_online_execute_round_1(asymoff_sign_cmp_data_t *party) {

  if (party->i == 0) return 1;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_1(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;


  return 0;
}

int asymoff_signing_online_execute_round_2(asymoff_sign_cmp_data_t *party) {
  pinfo("Player %ld: Executing Round 2\n", party->i);

  //uint64_t num_parties = party->num_parties;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_2(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;

  return 0;
}


int asymoff_signing_online_execute_round_3(asymoff_sign_cmp_data_t *party) {
  pinfo("Player %ld: Executing Round 3\n", party->i);

  //uint64_t num_parties = party->num_parties;

  return 0;
}

uint64_t asymoff_signing_send_online_msg_3(asymoff_sign_cmp_data_t *sender, asymoff_sign_cmp_data_t *receiver) {
  if (sender->i == 0) return 0;

  return 0;
}

int asymoff_signing_online_execute_final(asymoff_sign_cmp_data_t *party) {
  pinfo("Player %ld: Executing Finalizationization\n", party->i);
  
  if (party->i == 0) return 0;
  
  return 0;
}

void asymoff_signing_export_data(asymoff_party_data_t **parties, asymoff_sign_cmp_data_t ** const presign_parties) {
  
  //uint64_t num_parties = parties[0]->num_parties;
  //ec_group_t ec        = parties[0]->ec;

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
