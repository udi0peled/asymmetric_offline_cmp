#!/bin/bash

PARAMS="-no-print -mock-key"

# for NUM_PARTIES in 2 3 5 
# do
#   for PRE_SIGN in 200 250 300 350 400 450 500
#   do
#     { time ../benchmark -pre $PRE_SIGN  -sign 1     -parties $NUM_PARTIES $PARAMS;} &> run_1_pack_"$NUM_PARTIES"_parties_"$PRE_SIGN"_presign.txt
#   done
# done

# for NUM_PARTIES in 7 
# do
#   for PRE_SIGN in 100
#   do
#     { time ../benchmark -pre $PRE_SIGN  -sign 100     -parties $NUM_PARTIES $PARAMS;} &> run_sign_100_"$NUM_PARTIES"_parties_"$PRE_SIGN"_presign.txt
#   done
# done

{ time ../benchmark  -sign 3 -parties 3 -no-print -mock-key -pre 100000;} &> full_100K.txt
{ time ../benchmark  -sign 3 -parties 3 -no-print -mock-key -pre 100000 -light;} &> light_100K.txt

