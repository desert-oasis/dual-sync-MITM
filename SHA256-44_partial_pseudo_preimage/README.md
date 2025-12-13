# Pseudo-preimage attack on 44-step SHA-256

A C++ implementation of partial-target pseudo-preimage attack on 44-step SHA-256 without the padding rule.

## Build

**Requires C++11 or newer.**
Just run:

```
make
```

## What the program does

- Finds messages that such that 25 output bits of set to zeros for 44-step SHA-256.

- **Target detail**: realizes an **25-bit partial matching** on state word **A44=Hash[0:31]-A0**, where Hash is the output of 44-step SHA-256 and set Hash[0:31]=0:

  - **5 bits** from $S^{match}$: A44[0:4]
  - **20 additional bits**: A44[5:24]

- **Parameters (defauts in code)**

  - total loops: $2^{25}$, where external loop is $2^{17}$ and internal loop is $2^{d_f} + 2^{d_b}$ where $d_f=5, d_b=8, d_m=5$
  - backward probablity that backward 3-step extension is $Pr_{b} = 0.5$

- When run, the program reports:

  - **Expriment Result** — the experimental number of messages such that 25-bit partial target set to zeros, that is partial matching on A44[0:24]
     In generic attack, after $2^{25}$ tests, there is only one message such that 25-bit partial target. 

     In our experiment, there are, on average, ~$2^{4}$ messages such that 25-bit partial target, which indicates the attack find a partial target pseudo-preimage take $O(1/2^4)$ loops, and the advantage is 4 bits. (not 5 bits, due to $Pr_{b} = 0.5$)

  - **Ratio** — the ratio between the **experimental count** and the **theoretically expected count** of achieving the above 25-bit partial target.
     Interpretation: **ratio ≥ 1** indicates the experiment **meets or exceeds** the expected.

## Example

Example run:

```
$ ./bin/SHA256-44_partial_target
########## Experiment Infos ###########
In expriemnt, the number of total loops: 2^25
    - the external loops = 2^17
    - internal loops = (2^{d_f} + 2^{d_b}), where (d_f = 5, d_b = 8, d_m = 5)

########## Experiment Result ###########
The partial target is 25-bit Hash[0:24] (set to 0^25):
    - the exprimental number of messages s.t. partial matching on A44[0:24]: N_expriment = 17
    - on average, finding a partial target pseudo-preimage takes O(1/17), that is, advantage is 4 bits

########## Complexity Analysis #########
The expected number of messages s.t. partial matching on A44[0:24]:
    - on average, N_expect = 2^{17+d_f+d_b-d_m-20}*0.5 = 16
    - the ratio (N_expriment/N_expect) = 1.06
```

## ⚠️ Disclaimer

This code is for research and learning purposes. It **has not been audited** for security or standards compliance. Do not use it where security matters. Prefer well-maintained libraries such as OpenSSL.
