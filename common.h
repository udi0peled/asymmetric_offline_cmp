/**
 * 
 *  Name:
 *  common
 *  
 *  Description:
 *  Common printing function for bytes, bignums and ec points.
 * 
 */

#ifndef __ASYMOFF_COMMON_H__
#define __ASYMOFF_COMMON_H__

#include <string.h>
#include <assert.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <stdarg.h>
#include <time.h>

#define ENABLE_TIME(tag) \
clock_t start_time_##tag, end_time_##tag; \
static void start_timer() { start_time_##tag = clock(); } \
static double get_time(const char* str) { \
  end_time_##tag = clock(); \
  double diff_time = ((double)(end_time_##tag - start_time_##tag)) /CLOCKS_PER_SEC; \
  if (str) { pinfo("%s", str); pinfo("%f\n", diff_time); } \
  return diff_time; } \
   

void printHexBytes(const char * prefix, const uint8_t *src, unsigned len, const char * suffix, int print_len);
void printBIGNUM(const char * prefix, const BIGNUM *bn, const char * suffix);
void printECPOINT(const char * prefix, const EC_POINT *p, const EC_GROUP *ec, const char * suffix, int print_uncompressed);

void pinfo(const char *format, ...);

#endif