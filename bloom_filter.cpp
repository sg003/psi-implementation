#include "bloom_filter.hpp"
#include <openssl/sha.h>
#include <cmath>
#include <string>

size_t bf_optimal_size(size_t v, size_t k) {
    return static_cast<size_t>(std::ceil((v * k) / std::log(2.0)));
}

BloomFilter bf_init(size_t m, size_t k) {
    BloomFilter bf;
    bf.bits = std::vector<int>(m, 1);
    bf.m = m;
    bf.k = k;
    return bf;
}

size_t bf_hash(const std::string& s, size_t i, size_t m) {
    std::string salted = s + std::to_string(i);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(salted.data()), salted.size(), digest);

    size_t result = 0;
    for (int j = 0; j < 8; ++j)
        result = (result << 8) | digest[j];

    return result % m;
}

void bf_add(BloomFilter& bf, const std::string& s) {
    for (size_t i = 0; i < bf.k; i++) {
        size_t index = bf_hash(s, i, bf.m);
        bf.bits[index] = 0;
    }
}

bool bf_check(const BloomFilter& bf, const std::string& s) {
    for (size_t i = 0; i < bf.k; i++) {
        size_t index = bf_hash(s, i, bf.m);
        if (bf.bits[index] != 0)
            return false;
    }
    return true;
}
