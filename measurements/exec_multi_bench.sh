#!/usr/bin/bash

# { time ../benchmark 1 ;} &> 3P_batch_1.txt
# { time ../benchmark 10 ;} &> 3P_batch_10.txt
# { time ../benchmark 100 ;} &> 3P_batch_100.txt
# { time ../benchmark 1000 ;} &> 3P_batch_1K.txt
{ time ../benchmark 10000 ;} &> 3P_batch_10K.txt