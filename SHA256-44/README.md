# Preimage attack on 44-step SHA-256

A C++ implementation of **Algorithm 2** (steps **1–25**) for a preimage attack on 44-step SHA-256.

## Build

**Requires C++11 or newer.**
Just run:

```
make
```

## What the program does

- Implements **steps 1–25** of Algorithm 2 in the paper.
- Realizes an **8-bit partial matching** on state word **A37**:
  - **5 bits** from S^{match}: **A37[0:4]**
  - **3 additional bits** via indirect constraints: **A37[5:7]**
- When run, the program reports:
  1. Pr⁡b — the estimated probability that a **3-step backward extension** is correct.
  2. **ratio** — the ratio between the **experimental count** and the **theoretically expected count** of achieving the above **8-bit partial matching**.
     Interpretation: **ratio ≥ 1** indicates the experiment **meets or exceeds** the expected theoretic complexity.

## Parameters (defaults in code)

- df=5, db=8, dm=5

- Number of samples: Nsample=2^17=131072

- Expected count formula used in code:

  Nexpect=Nsample×2^{df+db−dm−3}×0.5.

  With the defaults, 2^{5+8−5−3}=2^5=32, hence
  Nexpect=131072×32×0.5=2,097,152.

## Example

Example run:

```
$ ./bin/SHA256
Number of total samples: 131072
1. re-estimate Pr_b = Pr[correctly expand three steps in backward]: 0.5
2. ratio (N_expriment/N_expect) = 1.04>= 1 means the experiment verifies the expected theoretic complexity.
    - where N_expect (expected number of partial matching on A37[0:4, 5:7]): N_sample*(1<<(d_f+d_b-d_m-3))*0.5 = 2097152.00
    - and N_expriment (true number of partial matching on A37[0:4, 5:7]) = 2183507
```

## ⚠️ Disclaimer

This code is for research and learning purposes. It **has not been audited** for security or standards compliance. Do not use it where security matters. Prefer well-maintained libraries such as OpenSSL.
