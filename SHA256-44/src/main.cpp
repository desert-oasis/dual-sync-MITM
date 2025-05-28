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
void PseudoPreimage_MITM();


int main(int argc, char ** argv) {

    PseudoPreimage_MITM();

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

void FindIS(std::vector<std::vector<uint32_t>> p22, std::vector<std::vector<uint32_t>> p18){
    int d_f=7,d_b=3;
    uint32_t mask_forward=0x01fc0000; //W18, {18:24}
    uint32_t mask_backward=0x00000007; //W21, {0:2}

    //According to Proposition 11 in Appendix, we obtain a valid initial structure by the following way
    uint32_t rands[8];
    generateRandomUInt32Array(rands,8);

    uint32_t p19[8];
    uint32_t W18;//forward neutral word
    uint32_t W19=0;//arbitrary value, set zero for simplicity
    uint32_t W20;//message compensation: W20=sig1(W18);
    uint32_t W21;//backward neutral word

    uint32_t E_prime_19=0;//E'19, from Proposition 11 in Appendix

    for(uint32_t index_W18=0;index_W18<(1<<d_f);index_W18++){
        W18=(index_W18<<18);
        W20=sig1(W18);
        
        p19[0]=W18+rands[0];//A19
        p19[1]=rands[1];//B19
        p19[2]=rands[2];//C19
        p19[3]=rands[3];//D19
        p19[4]=W18+E_prime_19; //E19, satisfy E19[0:2]=000
        p19[5]=rands[5];//F'19, actually, F19+W21
        p19[6]=rands[6];//G19
        p19[7]=rands[7];//H19

        uint32_t xorE = rotr(p19[4], 6) ^ rotr(p19[4], 11) ^ rotr(p19[4], 25);
        uint32_t tmp = p19[3] + xorE + choose(p19[4],p19[5],p19[6]) + W19 + K[19];
        int value = tmp&mask_backward;
        //set H19 such that E20[0:2]=111
        p19[7] = (p19[7]&~mask_backward) | (~value);

        uint32_t p_tmp[8];
        for(int k=0;k<8;k++) p_tmp[k]=p19[k];
        StepFunction(p_tmp,W19,19); //p20
        StepFunction(p_tmp,W20,20); //p21
        StepFunction(p_tmp,0x00000004,21); //p22, with W21=0x00000004;//fixed setting
 
        for(int k=0;k<8;k++) p22[index_W18][k]=p_tmp[k];
    }

    for(uint32_t index_W21=0;index_W21<(1<<d_b);index_W21++){
        W21=index_W21;

        p19[0]=rands[0];//A'19, A19-W18
        p19[1]=rands[1];//B19
        p19[2]=rands[2];//C19
        p19[3]=rands[3];//D19
        p19[4]=E_prime_19; //E'19, E19-W18
        p19[5]=rands[5]-W21;//F19
        p19[6]=rands[6];//G19
        p19[7]=rands[7];//H19

        uint32_t xorE = rotr(p19[4], 6) ^ rotr(p19[4], 11) ^ rotr(p19[4], 25);
        uint32_t tmp = p19[3] + xorE + choose(p19[4],(p19[5]+W21),p19[6]) + W19 + K[19];
        int value = tmp&mask_backward;
        //set H19 such that E20[0:2]=111
        p19[7] = (p19[7]&~mask_backward) | (~value);

        uint32_t p_tmp[8];
        for(int k=0;k<8;k++) p_tmp[k]=p19[k];
        InvStepFunction(p_tmp,0x01000000,18); //W18=0x01000000;//fixed setting

        for(int k=0;k<8;k++) p18[index_W21][k]=p_tmp[k];
    }
}

void PseudoPreimage_MITM(){
	int d_f=7,d_b=3,d_m=3;
    uint32_t mask_forward=0x01fc0000; //W18, {18:24}
    uint32_t mask_backward=0x00000007; //W21, {0:2}
    uint32_t mask_match=0xe0000000; //A38, {29:31}

	//Precomputed phase, initial structure (IS)
    std::vector<std::vector<uint32_t>> p22((1<<d_f), std::vector<uint32_t>(8, 0));
    std::vector<std::vector<uint32_t>> p18((1<<d_b), std::vector<uint32_t>(8, 0));
    FindIS(p22,p18);


	//Online phase
    uint32_t N_sample=1<<17; int ctr_Pr_f=0; int ctr_partial_match=0;
    std::cout<<"Number of total samples: " << N_sample << std::endl;
    //For external variables of IS: W23
    uint32_t W32;
    for (W32 = 0; W32 < N_sample; ++W32)
    {   
        uint32_t W[44];
        W[32]=W32;
        W[19]=0,W[17]=0,W[16]=0,W[15]=0,W[14]=0,W[13]=0;//arbitrary value, set zero for simplicity

        MultiHashTable<int, int> hashTable((1<<d_f));
        std::vector<std::vector<uint32_t>> auxiTable((1<<d_f), std::vector<uint32_t>(8, 0));
        std::vector<uint32_t> auxiTableW36((1<<d_f), 0);
        std::vector<uint32_t> auxiTableW37((1<<d_f), 0);
        std::vector<std::vector<uint32_t>> auxiTableWW((1<<d_f), std::vector<uint32_t>(6, 0));

        //Forward computation
        for(int i=0; i<(1<<d_f); i++){ //W18
            //message compensation
            W[18]=i<<18;
            W[20]=sig1(W[18]);
            W[22]=sig1(W[20]);
            W[24]=sig1(W[22]);
            W[26]=sig1(W[24]);
            W[28]=sig1(W[26]);
            W[25]=W[18];
            W[27]=sig1(W[18])+sig1(W[18]);
            std::vector<int> vec = {20, 22, 24, 26, 28, 25, 27};

            uint32_t p_tmp[8];
            for(int k=0;k<8;k++) p_tmp[k]=p22[i][k];

            for(int j=22;j<37-1;j++){
                if(isNotInVector(j,vec)) W[j] = sig1(W[j-2]) + W[j-7] + sig0(W[j-15]) + W[j-16];
                StepFunction(p_tmp,W[j],j);
            }
            for(int k=0;k<8;k++) auxiTable[i][k]=p_tmp[k]; //p36

            uint32_t W21=0x00000004;//fixed setting
            uint32_t W36 = sig1(W[34]) + W[29] + sig0(W21) + W[20];
            uint32_t W37 = sig1(W[35]) + W[30] + sig0(W[22]) + W21;
            StepFunction(p_tmp,W36,36); //p37
            StepFunction(p_tmp,W37,37); //p38
            auxiTableW36[i] = sig1(W[34]) + W[29] + W[20];
            auxiTableW37[i] = sig1(W[35]) + W[30] + sig0(W[22]);
            for(int j=38;j<44;j++) {
                W[j] = sig1(W[j-2]) + W[j-7] + sig0(W[j-15]) + W[j-16];
                auxiTableWW[i][j-38];
            }

            uint32_t A38=p_tmp[0];
            int value=(A38&mask_match)>>(32-d_m);
            hashTable.insert(value,i);
        }

        //Backward computation
        for(int i=0; i<(1<<d_b); i++){ //W21
            W[21]=i;
            
            uint32_t p_tmp[8];
            for(int k=0;k<8;k++) p_tmp[k]=p18[i][k];
            
            for(int j=17;j>1+1;j--){
                if(j<13) W[j] = W[j+16] - sig1(W[j+14]) - W[j+9] - sig0(W[j+1]);
                InvStepFunction(p_tmp,W[j],j);
            }
            //p3
            uint32_t p3[8];
            for(int k=0;k<8;k++) p3[k]=p_tmp[k];

            uint32_t W18=0x01000000;//fixed setting
            uint32_t W2 = W18 - sig1(W[16]) - W[11] - sig0(W[3]);
            uint32_t W1 = W[17] - sig1(W[15]) - W[10] - sig0(W2);
            InvStepFunction(p_tmp,W2,2); //p2
            InvStepFunction(p_tmp,W1,1); //p1

            uint32_t H1=p_tmp[7];
            int value=(H1&mask_match)>>(32-d_m);
            std::vector<int> all_index_W18 = hashTable.findAll(value);
            for (int index_W18 : all_index_W18) {
                uint32_t p_tmp_recomputed[8];
                for(int k=0;k<8;k++) p_tmp_recomputed[k]=auxiTable[index_W18][k]; //p36

                uint32_t W36 = auxiTableW36[index_W18] + sig0(i);
                uint32_t W37 = auxiTableW37[index_W18] + i;
                StepFunction(p_tmp_recomputed,W36,36); //p37
                StepFunction(p_tmp_recomputed,W37,37); //p38

                uint32_t A38_recomputed=p_tmp_recomputed[0];
                int value_recomputed=(A38_recomputed&mask_match)>>(32-d_m);

                if(value_recomputed==value) {
                    ctr_Pr_f++;

                    uint32_t p_tmp[8];
                    for(int k=0;k<8;k++) p_tmp[k]=p3[k];
                    uint32_t W18=index_W18<<18;//fixed setting
                    uint32_t W2 = W18 - sig1(W[16]) - W[11] - sig0(W[3]);
                    uint32_t W1 = W[17] - sig1(W[15]) - W[10] - sig0(W2);
                    InvStepFunction(p_tmp,W2,2); //p2
                    InvStepFunction(p_tmp,W1,1); //p1
                    W[0] = W[16] - sig1(W[14]) - W[9] - sig0(W[1]);
                    InvStepFunction(p_tmp,W[0],0);

                    //Assume Hash==0
                    for(int j=43;j>38-1;j--) {
                        InvStepFunction(p_tmp,auxiTableWW[index_W18][j-38],j);
                    }

                    //A38[0:1]
                    uint32_t mask_partial_match=0x00000003;
                    if((p_tmp[0]&mask_partial_match)==(A38_recomputed&mask_partial_match)) ctr_partial_match++;
                }
            }
        }
    }

    double pr_f=(double)ctr_Pr_f/(double)(N_sample*(1<<(d_f+d_b-d_m)));
    std::cout<<"    - Re-estimate Pr_f = Pr[correctly expand two steps in forward]: " << std::fixed << std::setprecision(1) << pr_f << std::endl;

    double N_expect=N_sample*(1<<(d_f+d_b-d_m-2))*0.7;
    std::cout<<"    - N_expect (expected number of partial matching on A38[29:31] and A38[0:1]): N_sample*(1<<(d_f+d_b-d_m-2))*0.7 = " << N_expect << std::endl;
    std::cout<<"    - N_expriment (true number of partial matching on A38[29:31] and A38[0:1]) = " <<ctr_partial_match << std::endl;
    std::cout<<"    - N_expriment/N_expect = " << std::fixed << std::setprecision(2) << (double)ctr_partial_match/(double)N_expect << std::endl;
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