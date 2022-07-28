/**
 * 
 *  Name:
 *  zkp_common
 *  
 *  Description:
 *  Common constants, structures and operations for zero-knowledge proofs relevant for the CMP protocol.
 *  To get a better understanding of these, consult the CMP article.
 * 
 *  Usage:
 *  zkp_aux_info_t contains info which is used (hashed) to generate a zkp challenge, this info defines the "session" of a zkp instantiation (but not the data of the zkp).
 *  The user of aux_info should encode the relevant values into bytes to be kept in the structure's info, but can update and extend the initial info bytes.
 *  fiat_shamir_<...> deterministically generates wanted number of pseudo-uniform bytes/scalars in range from an initial public data "seed".
 * 
 */

#include <inttypes.h>

#ifndef __ASYMOFF_ZKP_COMMON_H__
#define __ASYMOFF_ZKP_COMMON_H__

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include "algebraic_elements.h"
#include "paillier_cryptosystem.h"
#include "ring_pedersen_parameters.h"

#define PAILLIER_MODULUS_BYTES (8*GROUP_ORDER_BYTES)
#define RING_PED_MODULUS_BYTES (4*GROUP_ORDER_BYTES)

#define STATISTICAL_SECURITY 80

#define EPS_ZKP_SLACK_PARAMETER_BYTES (2*GROUP_ORDER_BYTES)
#define ELL_ZKP_RANGE_PARAMETER_BYTES (GROUP_ORDER_BYTES)
// #define ELL_PRIME_ZKP_RANGE_PARAMETER_BYTES (5*GROUP_ORDER_BYTES)
#define CALIGRAPHIC_I_ZKP_RANGE_BYTES (ELL_ZKP_RANGE_PARAMETER_BYTES)
#define CALIGRAPHIC_J_ZKP_RANGE_BYTES (EPS_ZKP_SLACK_PARAMETER_BYTES + ELL_ZKP_RANGE_PARAMETER_BYTES*3)

#define PACKING_SIZE 3

typedef struct
{
  uint8_t *info;
  uint64_t info_len;
} zkp_aux_info_t;

// Initialize information. If init_bytes==NULL assume zeros.
zkp_aux_info_t *
     zkp_aux_info_new         (uint64_t init_byte_len, const void *init_bytes);
void zkp_aux_info_free        (zkp_aux_info_t *aux);
// Update bytes starting from at_pos.
// If total needed length for update is longer then existing, extends aux info and length.
// If update_bytes==NULL, only extend/truncate to needed length, and set zeros where extended.
void zkp_aux_info_update      (zkp_aux_info_t *aux, uint64_t at_pos, const void *update_bytes, uint64_t update_byte_len);
// Same as above, but update at_pos to end of updated bytes (if exist)
void zkp_aux_info_update_move (zkp_aux_info_t *aux, uint64_t *at_pos, const void *update_bytes, uint64_t update_byte_len);

void fiat_shamir_bytes            (uint8_t *digest, uint64_t digest_len, const uint8_t *data, uint64_t data_len);
void fiat_shamir_scalars_in_range (scalar_t *results, uint64_t num_res, const scalar_t range, const uint8_t *data, uint64_t data_len);

void pack_plaintexts(scalar_t packed, const scalar_t *plaintexts, uint64_t packing_size, scalar_t domain, int test_decoding);
void unpack_plaintexts(scalar_t *unpacked, uint64_t packing_size, const scalar_t packed_plaintext);

scalar_t  *new_scalar_array(uint64_t len);
gr_elem_t *new_gr_el_array(uint64_t len, ec_group_t ec);

void free_scalar_array(scalar_t *scalars, uint64_t len);
void free_gr_el_array(gr_elem_t *grels, uint64_t len);

void copy_scalar_array(scalar_t *copy, scalar_t *source, uint64_t len);
void copy_gr_el_array(gr_elem_t *copy, gr_elem_t *source, uint64_t len);

#endif