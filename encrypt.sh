#!/bin/sh

for alg in "cfb" "cbc"; do
  for bitsize in "128" "192" "256"; do
    for i in $(seq 1 256); do
      echo $bitsize $alg $i
      nice -n -20 ./aes-bench $bitsize $alg $i >> encrypt-$alg-$bitsize.data
    done;
  done;
done;

