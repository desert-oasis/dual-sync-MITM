# Preimage attack on 44-step SHA-256

A C++ implementation of Alogorithm 3: preimage attack on 44-step SHA-256.

## Build

**Minimum C++11.**

Just run `make all`. There are no dependencies.

## ⚠️ DISCLAIMER

This library has been developed for research and learning purposes. It **has not been audited** for security nor compliance with the standard. It is not advised to use it in projects where security is important. Use wide-spread and reliable libraries such as [OpenSSL](https://www.openssl.org/) instead.

## Example usage

### Sample program

Re-estimate Pr_f, which is the probalility of correctly expand two steps in forward with with partial-fixing.

Verify the theoretical analysis: if the experimental number of partial matching is basically same with the theoretically expected one. 

```
$ ./bin/SHA256
Number of total samples: 131072
    - Re-estimate Pr_f = Pr[correctly expand two steps in forward]: 0.7
    - N_expect (expected number of partial matching on A38[29:31] and A38[0:1]): N_sample*(1<<(d_f+d_b-d_m-2))*0.7 = 2936012.8
    - N_expriment (true number of partial matching on A38[29:31] and A38[0:1]) = 3276800
    - N_expriment/N_expect = 1.12
```
