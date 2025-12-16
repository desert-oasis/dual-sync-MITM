#include <iostream>
#include <chrono>
#include <ctime>
#include "SHA256.h"
#include <vector>
#include <list>
#include <string>
#include <utility>
#include <functional>
#include <random>
#include <bitset>
#include <cassert>
#include <iomanip>
#include <algorithm>


uint32_t rotr(uint32_t x, uint32_t n);
uint32_t choose(uint32_t e, uint32_t f, uint32_t g);
uint32_t majority(uint32_t a, uint32_t b, uint32_t c);
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);
void StepFunction(uint32_t *state, uint32_t m, uint8_t iR);
void InvStepFunction(uint32_t *state, uint32_t m, uint8_t iR);
void generateRandomUInt32Array(uint32_t *array, size_t size);
void RunTrials_Median(int T, int size_partial_target);


int main(int argc, char ** argv) {

    // Partial target pseudo-preimage attack on 44-step SHA-256
    int num_trials = 10;
    int size_partial_target = 32;
    
    // int size_partial_target = 40;

    std::cout << "Target: find a message such that "
          << size_partial_target
          << "-bit partial target, "
          << "total #trials= " << num_trials << ":"
          << std::endl;

    RunTrials_Median(num_trials, size_partial_target);

    return EXIT_SUCCESS;
}


// sha-256 round constants
std::array<uint32_t, 64> K = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

template <typename KeyType, typename ValueType>
class MultiHashTable {
private:
    struct HashNode {
        KeyType key;
        ValueType value;
        HashNode(const KeyType& k, const ValueType& v) : key(k), value(v) {}
    };
    
    std::vector<std::list<HashNode>> table;
    size_t size;
    size_t capacity;
    
    size_t hash(const KeyType& key) const {
        return std::hash<KeyType>()(key) % capacity;
    }
    
public:
    MultiHashTable(size_t cap) : capacity(cap), size(0) {
        table.resize(capacity);
    }
    
    void insert(const KeyType& key, const ValueType& value) {
        size_t index = hash(key);
        table[index].emplace_back(key, value);
        size++;
    }
    
    std::vector<ValueType> findAll(const KeyType& key) const {
        std::vector<ValueType> results;
        size_t index = hash(key);
        for (const auto& node : table[index]) {
            if (node.key == key) {
                results.push_back(node.value);
            }
        }
        return results;
    }
    
    bool contains(const KeyType& key) const {
        size_t index = hash(key);
        for (const auto& node : table[index]) {
            if (node.key == key) {
                return true;
            }
        }
        return false;
    }
    
    void removeAll(const KeyType& key) {
        size_t index = hash(key);
        auto& bucket = table[index];
        size_t originalSize = bucket.size();
        
        bucket.remove_if([&key](const HashNode& node) {
            return node.key == key;
        });
        
        size -= (originalSize - bucket.size());
    }
    
    void remove(const KeyType& key, const ValueType& value) {
        size_t index = hash(key);
        auto& bucket = table[index];
        
        for (auto it = bucket.begin(); it != bucket.end(); ) {
            if (it->key == key && it->value == value) {
                it = bucket.erase(it);
                size--;
            } else {
                ++it;
            }
        }
    }
    
    size_t getSize() const {
        return size;
    }
    
    size_t countValues(const KeyType& key) const {
        size_t count = 0;
        size_t index = hash(key);
        
        for (const auto& node : table[index]) {
            if (node.key == key) {
                count++;
            }
        }
        
        return count;
    }
    
    void clear() {
        table.clear();
        table.resize(capacity);
        size = 0;
    }
};

bool isNotInVector(int number, const std::vector<int>& vec) {
    return std::find(vec.begin(), vec.end(), number) == vec.end();
}

void FindIS(std::vector<std::vector<uint32_t>> p29, std::vector<std::vector<uint32_t>> p25){
    int d_f=5,d_b=8;
    uint32_t mask_forward=0xf8000000; //W25, {27:31}
    uint32_t mask_backward=0x0000ff00; //W28, {8:15}

    //According to Proposition 1, we obtain a valid initial structure by the following way
    uint32_t rands[8];
    generateRandomUInt32Array(rands,8);

    uint32_t p26[8];
    uint32_t W25;//forward neutral word
    uint32_t W26=0;//arbitrary value, set zero for simplicity
    uint32_t W27;//message compensation: W27=sig1(W25);
    uint32_t W28;//backward neutral word

    uint32_t E_prime_26=0;//E'26, from Proposition 11 in Appendix

    for(uint32_t index_W25=0;index_W25<(1<<d_f);index_W25++){
        W25=(index_W25<<27);
        W27=sig1(W25);
        
        p26[0]=W25+rands[0];//A26
        p26[1]=rands[1];//B26
        p26[2]=rands[2];//C26
        p26[3]=rands[3];//D26
        p26[4]=W25+E_prime_26; //E26
        p26[5]=rands[5];//F'26, actually, F26+W28
        p26[6]=rands[6];//G26
        p26[7]=rands[7];//H26

        uint32_t xorE = rotr(p26[4], 6) ^ rotr(p26[4], 11) ^ rotr(p26[4], 25);
        uint32_t tmp = p26[3] + xorE + choose(p26[4],p26[5],p26[6]) + W26 + K[26];
        int value = tmp&mask_backward;
        //set H26
        p26[7] = (p26[7]&~mask_backward) | (~value);

        uint32_t p_tmp[8];
        for(int k=0;k<8;k++) p_tmp[k]=p26[k];
        StepFunction(p_tmp,W26,26); //p27
        StepFunction(p_tmp,W27,27); //p28
        StepFunction(p_tmp,0x00008000,28); //p29: W28, with this fixed setting
 
        for(int k=0;k<8;k++) p29[index_W25][k]=p_tmp[k];
    }

    for(uint32_t index_W28=0;index_W28<(1<<d_b);index_W28++){
        W28=index_W28<<8;

        p26[0]=rands[0];//A'26, A26-W25
        p26[1]=rands[1];//B26
        p26[2]=rands[2];//C26
        p26[3]=rands[3];//D26
        p26[4]=E_prime_26; //E'26, E26-W25
        p26[5]=rands[5]-W28;//F26
        p26[6]=rands[6];//G26
        p26[7]=rands[7];//H26

        uint32_t xorE = rotr(p26[4], 6) ^ rotr(p26[4], 11) ^ rotr(p26[4], 25);
        uint32_t tmp = p26[3] + xorE + choose(p26[4],(p26[5]+W28),p26[6]) + W26 + K[26];
        int value = tmp&mask_backward;
        //set H26
        p26[7] = (p26[7]&~mask_backward) | (~value);

        uint32_t p_tmp[8];
        for(int k=0;k<8;k++) p_tmp[k]=p26[k];
        InvStepFunction(p_tmp,0x80000000,25); //W25, with this fixed setting

        for(int k=0;k<8;k++) p25[index_W28][k]=p_tmp[k];
    }
}

struct PrecompIS {
    int d_f, d_b, d_m;
    std::vector<std::vector<uint32_t>> p29;
    std::vector<std::vector<uint32_t>> p25;
};

static PrecompIS BuildIS(int d_f, int d_b, int d_m) {
    PrecompIS is;
    is.d_f = d_f; is.d_b = d_b; is.d_m = d_m;
    is.p29.assign((1 << d_f), std::vector<uint32_t>(8, 0));
    is.p25.assign((1 << d_b), std::vector<uint32_t>(8, 0));
    FindIS(is.p29, is.p25);
    return is;
}

static uint64_t OneTrial_PseudoPreimage_MITM(const PrecompIS& is, int size_partial_target) {
    const int d_f = is.d_f, d_b = is.d_b, d_m = is.d_m;
    (void)d_m;

    uint32_t mask_forward  = 0xf8000000; //W25, {27:31}
    uint32_t mask_backward = 0x0000ff00; //W28, {8:15}
    uint32_t mask_match    = 0x0000001f; // A44, {0:4}
    (void)mask_forward; (void)mask_backward;

    uint64_t loop = 0;
    bool done = false;

    while (!done) {
        loop++;

        uint32_t W[44];

        uint32_t rands[7];
        generateRandomUInt32Array(rands, 7);

        W[39]=rands[6];
        W[26]=rands[0], W[24]=rands[1], W[23]=rands[2];
        W[22]=rands[3], W[21]=rands[4], W[20]=rands[5];

        MultiHashTable<int, int> hashTable((1<<d_f));
        std::vector<std::vector<uint32_t>> auxiTable((1<<d_f), std::vector<uint32_t>(8, 0));
        std::vector<uint32_t> auxiTableW43((1<<d_f), 0);
        std::vector<std::vector<uint32_t>> auxiTableWW((1<<d_f), std::vector<uint32_t>(7, 0));

        // Forward computation
        for(int i=0; i<(1<<d_f); i++){ // W25
            W[25]=((uint32_t)i)<<27;
            W[27]=sig1(W[25]);
            W[29]=sig1(W[27]);
            W[31]=sig1(W[29]);
            W[33]=sig1(W[31]);
            W[35]=sig1(W[33]);
            W[32]=W[25];
            W[34]=sig1(W[25])+sig1(W[25]);
            std::vector<int> vec = {27, 29, 31, 33, 35, 32, 34};

            uint32_t p_tmp[8];
            for(int k=0;k<8;k++) p_tmp[k]=is.p29[i][k];

            for(int j=29; j<44-1; j++){
                if(isNotInVector(j, vec))
                    W[j] = sig1(W[j-2]) + W[j-7] + sig0(W[j-15]) + W[j-16];
                StepFunction(p_tmp, W[j], j);
            }
            for(int k=0;k<8;k++) auxiTable[i][k]=p_tmp[k]; // p43

            uint32_t W43 = sig1(W[41]) + W[36] + W[27];
            auxiTableW43[i] = W43;
            StepFunction(p_tmp, W43, 43); // p44

            for(int j=0;j<7;j++) {
                W[j] = W[j+16] - sig1(W[j+14]) - W[j+9] - sig0(W[j+1]);
                auxiTableWW[i][j] = W[j];
            }

            uint32_t A44 = p_tmp[0];
            int value = (int)(A44 & mask_match);
            hashTable.insert(value, i);
        }

        // Backward computation
        for(int i=0; (i<(1<<d_b)) && !done; i++){ // W28
            W[28]=((uint32_t)i)<<8;

            uint32_t p_tmp[8];
            for(int k=0;k<8;k++) p_tmp[k]=is.p25[i][k];

            for(int j=24; j>8+1; j--){
                if(j<20) W[j] = W[j+16] - sig1(W[j+14]) - W[j+9] - sig0(W[j+1]);
                InvStepFunction(p_tmp, W[j], j);
            }

            uint32_t p10[8];
            for(int k=0;k<8;k++) p10[k]=p_tmp[k];

            uint32_t W25_fixed=0x80000000;
            uint32_t W9 = W25_fixed - sig1(W[23]) - W[18] - sig0(W[11]);
            uint32_t W8 = W[24] - sig1(W[22]) - W[17] - sig0(W9);
            uint32_t W7 = W[23] - sig1(W[21]) - W[16] - sig0(W8);
            InvStepFunction(p_tmp, W9, 9);
            InvStepFunction(p_tmp, W8, 8);
            InvStepFunction(p_tmp, W7, 7);

            // Assume Hash==0, since A0+A44=Hash, then A44=Hash-A0, where A0=H7
            uint32_t H7 = 0 - (p_tmp[7] - sig0(W[28]));
            int value = (int)(H7 & mask_match);

            std::vector<int> all_index_W25 = hashTable.findAll(value);
            for (int index_W25 : all_index_W25) {
                uint32_t p_tmp_recomputed_7[8];
                for(int k=0;k<8;k++) p_tmp_recomputed_7[k]=p10[k];

                uint32_t W25 = ((uint32_t)index_W25)<<27;
                uint32_t W9r = W25 - sig1(W[23]) - W[18] - sig0(W[11]);
                uint32_t W8r = W[24] - sig1(W[22]) - W[17] - sig0(W9r);
                uint32_t W7r = W[23] - sig1(W[21]) - W[16] - sig0(W8r);
                InvStepFunction(p_tmp_recomputed_7, W9r, 9);
                InvStepFunction(p_tmp_recomputed_7, W8r, 8);
                InvStepFunction(p_tmp_recomputed_7, W7r, 7);

                // Assume Hash==0, since A0+A44=Hash, then A44=Hash-A0, where A0=H7
                uint32_t H7_recomputed = 0 - (p_tmp_recomputed_7[7] - sig0(W[28]));
                int value_recomputed = (int)(H7_recomputed & mask_match);

                if(value_recomputed == value) {
                    uint32_t p_tmp_recomputed[8];
                    for(int k=0;k<8;k++) p_tmp_recomputed[k]=auxiTable[index_W25][k];

                    uint32_t W43r = auxiTableW43[index_W25];
                    StepFunction(p_tmp_recomputed, W43r, 43);
                    uint32_t A44_recomputed = p_tmp_recomputed[0];
                    uint32_t B44_recomputed = p_tmp_recomputed[1];

                    bool flag_match = true;

                    auto low_mask = [](int bits) -> uint32_t {
                        // returns mask for low 'bits' bits, bits in [0..32]
                        if (bits <= 0) return 0u;
                        if (bits >= 32) return 0xFFFFFFFFu;
                        return (1u << bits) - 1u;
                    };

                    // 1) Match A44 low bits
                    int bits_A = std::min(size_partial_target, 32);
                    uint32_t mask_A = low_mask(bits_A);

                    // Assume Hash==0, since A0+A44=Hash, then A44=Hash-A0, where A0=H7
                    if( ((0 - (p_tmp_recomputed_7[7] - sig0(W[28]))) & mask_A)
                        != (A44_recomputed & mask_A) )
                        flag_match = false;

                    // 2) If need more bits, match B44 low bits
                    if (flag_match && size_partial_target > 32) {
                        for(int j=6; j>=0; j--) {
                            InvStepFunction(p_tmp_recomputed_7, auxiTableWW[index_W25][j], j);
                        }

                        int bits_B = size_partial_target - 32;          // in [1..32]
                        uint32_t mask_B = low_mask(bits_B);

                        // Hash==0 => B44 = -B0 (mod 2^32)
                        uint32_t B44_target = 0u - p_tmp_recomputed_7[1];

                        if ( (B44_target & mask_B) != (B44_recomputed & mask_B) )
                            flag_match = false;
                    }

                    if(flag_match) {
                        done = true;
                        break;
                    }
                }
            }
        }
    }

    return loop;
}

static uint64_t median_u64(std::vector<uint64_t> v) {
    const size_t n = v.size();
    if (n == 0) return 0;

    const size_t mid = n / 2;
    std::nth_element(v.begin(), v.begin() + mid, v.end());
    uint64_t hi = v[mid];

    if (n % 2 == 1) return hi;

    std::nth_element(v.begin(), v.begin() + mid - 1, v.end());
    uint64_t lo = v[mid - 1];

    return (lo / 2) + (hi / 2) + ((lo & 1) && (hi & 1));
}

void RunTrials_Median(int T, int size_partial_target) {
    const int d_f=5, d_b=8, d_m=5;
    PrecompIS is = BuildIS(d_f, d_b, d_m);

    std::vector<uint64_t> loops;
    loops.reserve(T);

    auto t0 = std::chrono::high_resolution_clock::now();

    for (int t = 0; t < T; t++) {
        uint64_t L = OneTrial_PseudoPreimage_MITM(is, size_partial_target);
        loops.push_back(L);

        double log_cost = std::log2((double)L)
                        + std::max({d_f, d_b, d_m});

        std::cout << "  - trial " << (t+1) << "/" << T
                  << ": #loops ≈ 2^"
                  << std::fixed << std::setprecision(2)
                  << log_cost
                  << std::endl;
    }

    auto t1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> dt = t1 - t0;

    uint64_t med = median_u64(loops);

    const int d_internal = std::max({d_f, d_b, d_m});

    double median_log_cost = std::log2((double)med) + d_internal;

    std::cout << "\n===== Summary =====\n";
    std::cout << "Trials:          " << T << "\n";
    std::cout << "Median cost (#loops):     ≈ 2^"
              << std::fixed << std::setprecision(2)
              << median_log_cost << "\n";
    std::cout << "Total time:      " << dt.count() << " s\n";
}

void generateRandomUInt32Array(uint32_t *array, size_t size) {
    std::random_device rd; 
    std::mt19937 gen(rd());

    std::uniform_int_distribution<uint32_t> dis(0, UINT32_MAX); // 0 到 2^32 - 1

    for (size_t i = 0; i < size; ++i) {
        array[i] = dis(gen);
    }
}


void StepFunction(uint32_t state[8], uint32_t m, uint8_t iR){
    uint32_t maj, xorA, ch, xorE, sum, newA, newE;

    maj   = majority(state[0], state[1], state[2]);
    xorA  = rotr(state[0], 2) ^ rotr(state[0], 13) ^ rotr(state[0], 22);

    ch = choose(state[4], state[5], state[6]);

    xorE  = rotr(state[4], 6) ^ rotr(state[4], 11) ^ rotr(state[4], 25);

    sum  = m + K[iR] + state[7] + ch + xorE;
    newA = xorA + maj + sum;
    newE = state[3] + sum;

    state[7] = state[6];
    state[6] = state[5];
    state[5] = state[4];
    state[4] = newE;
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = newA;
}

void InvStepFunction(uint32_t state[8], uint32_t m, uint8_t iR){
    uint32_t maj, xorB, ch, xorF, sum, newD, newH, tmp;

    maj   = majority(state[1], state[2], state[3]);
    xorB  = rotr(state[1], 2) ^ rotr(state[1], 13) ^ rotr(state[1], 22);

    ch = choose(state[5], state[6], state[7]);

    xorF  = rotr(state[5], 6) ^ rotr(state[5], 11) ^ rotr(state[5], 25);

    sum = m + K[iR] + ch + xorF;
    tmp = state[0] - xorB - maj; 
    newH = tmp - sum;
    newD = state[4] - tmp;

    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = newD;
    state[4] = state[5];
    state[5] = state[6];
    state[6] = state[7];
    state[7] = newH;
}

uint32_t rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & (b | c)) | (b & c);
}

uint32_t sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint32_t sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}