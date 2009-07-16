#!/bin/sh

for i in $(seq 1 256); do
  ./aes-bench 128 cfb $i >> padding-cfb.data
done;

for i in $(seq 1 256); do
  ./aes-bench 128 cbc $i >> padding-cbc.data
done;
