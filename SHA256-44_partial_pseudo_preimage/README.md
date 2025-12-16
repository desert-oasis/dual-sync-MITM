# Pseudo-preimage attack on 44-step SHA-256

A C++ implementation of partial-target pseudo-preimage attack on 44-step SHA-256 without the padding rule.

## Build

**Requires C++11 or newer.**
Just run:

```
make
```

## What the program does

- Finds messages that such that $t=32$ or $40$ output bits of set to zeros for 44-step SHA-256.
- **Target detail**: realizes an **$t$-bit partial match** on state word **A44=Hash[0:31]-A0** and partial bits of **B44=Hash[32:63]-B0**, where Hash is the output of 44-step SHA-256 and set Hash[0:$t$]=0:
  - **5 bits** from $S^{match}$: A44[0:4]
  - **27 additional bits**: A44[5:31]
  - **$t-32$ additional bits**: B44[0:$t-32$]
- **Parameters (defauts in code)**
  - MitM attacks with $d_f=5, d_b=8, d_m=5$, and backward probablity that backward 3-step extension is $Pr_{b} = 0.5$.
  - total loops: $2^{n} = 2^{n'} \times (2^{d_f} + 2^{d_b} + 2^{d_f+d_b-d_m})$, where external loop is $2^{n'}$ and internal loop is $2^{d_f} + 2^{d_b} + + 2^{d_f+d_b-d_m}$. And, the process tests $Pr_{b} \times 2^{n'+d_f+d_b}$ message, that is it has an advantage of about $Pr_{b} \times \min(d_f,d_b,d_m)=4$ (not 5 bits, due to $Pr_{b} = 0.5$).
- When run, the program reports:

  - **Expriment Result** — the experimental number of loops (#loops) to find a message such that $t$-bit partial target set to zeros, that is the partial matching on A44[0:31] and B[32:$t$].
  - In our experiment of MitM attack, it takes, on average, $2^{28.02}$ loops to find messages such that 32-bit partial target, as expected.
  - In generic attack, after $2^{t}$ tests, there is one message such that $t$-bit partial target with probability about 0.6, where $t=32$ or $40$.
  -  That is, the attack has the advantage is $4 \approx (32-28.02)$ bits, which verifies the theoretic analysis.

## Example

Example run:

```
$ ./bin/SHA256-44_partial_target
Target: find a message such that 32-bit partial target, total #trials= 10:
  - trial 1/10: #loops ≈ 2^26.55
  - trial 2/10: #loops ≈ 2^29.20
  - trial 3/10: #loops ≈ 2^27.72
  - trial 4/10: #loops ≈ 2^28.26
  - trial 5/10: #loops ≈ 2^26.88
  - trial 6/10: #loops ≈ 2^27.70
  - trial 7/10: #loops ≈ 2^26.68
  - trial 8/10: #loops ≈ 2^29.51
  - trial 9/10: #loops ≈ 2^28.43
  - trial 10/10: #loops ≈ 2^28.36

===== Summary =====
Trials:          10
Median cost (#loops):     ≈ 2^28.02
Total time:      510.70 s

$ ./bin/SHA256-44_partial_target
Target: find a message such that 40-bit partial target, total #trials= 10:
  - trial 1/10: #loops ≈ 2^37.50
  - trial 2/10: #loops ≈ 2^31.76
  - trial 3/10: #loops ≈ 2^37.16
  - trial 4/10: #loops ≈ 2^35.34
  - trial 5/10: #loops ≈ 2^36.66
  - trial 6/10: #loops ≈ 2^33.37
  - trial 7/10: #loops ≈ 2^35.05
  - trial 8/10: #loops ≈ 2^35.36
  - trial 9/10: #loops ≈ 2^35.40
  - trial 10/10: #loops ≈ 2^37.40

===== Summary =====
Trials:          10
Median cost (#loops):     ≈ 2^35.38
Total time:      143813.12 s
```

## ⚠️ Disclaimer

This code is for research and learning purposes. It **has not been audited** for security or standards compliance. Do not use it where security matters. Prefer well-maintained libraries such as OpenSSL.
