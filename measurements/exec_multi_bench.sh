#!/bin/bash

PARAMS="-no-print -mock-key -mock-cmp"

for NUM_PARTIES in 2 3 5 7 10 12 15
do
  for SIGN in 999
  do
    { time ../benchmark -pre $SIGN  -sign $SIGN     -parties $NUM_PARTIES $PARAMS;} &> run_aggregate_3_pack_"$NUM_PARTIES"_parties_"$SIGN"_sign.txt
  done
done

# for NUM_PARTIES in 7 
# do
#   for PRE_SIGN in 100
#   do
#     { time ../benchmark -pre $PRE_SIGN  -sign 100     -parties $NUM_PARTIES $PARAMS;} &> run_sign_100_"$NUM_PARTIES"_parties_"$PRE_SIGN"_presign.txt
#   done
# done

# { time ../benchmark  -sign 3 -parties 3 -no-print -mock-key -pre 100000;} &> full_100K.txt
# { time ../benchmark  -sign 3 -parties 3 -no-print -mock-key -pre 100000 -light;} &> light_100K.txt

