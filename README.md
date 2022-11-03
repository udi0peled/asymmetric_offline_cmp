## About

This is a proof-of-concept implementation of [Efficient Asymmetric Threshold ECDSA for MPC-based Cold Storage](https://eprint.iacr.org/2022/1296/).

## Disclaimer

The code is only for demonstration and benchmarking purposes, do not use in production!

The code does not implement any communication between the parties, everything runs in a single process on the same machine and memory is shared between all parties.

## Usage

Build:
```
make
```

To generate 1000 persignatures, and sign 50 of them, between 5 parties (1 offline and 4 online):
```
./benchmark -pre 1000 -sign 50 -parties 5
```

To hide debug info add: `-no-print`.

To hide timing and communication measurements info add: `-no-measure`.

To save execution time it is possible to mock execution of some of the protocol phases, add:
* `-mock-key` to mock key generation phase.
* `-mock-pre` to mock presigning phase.
* `-mock-cmp` to mock CMP part of signing phase.
