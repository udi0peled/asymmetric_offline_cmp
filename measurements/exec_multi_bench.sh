#!/bin/bash

{ time ../benchmark 1 p;} &> 3P_batch_1.txt
{ time ../benchmark 10 p;} &> 3P_batch_10.txt
{ time ../benchmark 50 p;} &> 3P_batch_50.txt
{ time ../benchmark 100 p;} &> 3P_batch_100.txt
{ time ../benchmark 500 p;} &> 3P_batch_500.txt
{ time ../benchmark 1000 p;} &> 3P_batch_1000.txt
{ time ../benchmark 5000 1 p;} &> 3P_batch_5000.txt
{ time ../benchmark 10000 1 p;} &> 3P_batch_10000.txt