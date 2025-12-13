# dual-sync-MITM
- Folder 'SHA256-44': A C++ implementation of main steps of preimage attack on 44-step SHA-256 (Algorithm 2 in paper).

- Folder 'SHA256-44_partial_pseudo_preimage': A C++ implementation of partial-target pseudo-preimage attack on 44-step SHA-256 without the padding rule, where the matching point is moved to the end of compression function, i.e. match at the last step, compared to the one of 'SHA256-44'. 

  PS: As pointed in [23], for converting partial-target pseudo-preimage attacks to a (pseudo) collision attack, we do not need to control message words for satisfying the padding rules, since we can generate correct padding by simply adding another message block as discussed in Section 3.3 of [23].
