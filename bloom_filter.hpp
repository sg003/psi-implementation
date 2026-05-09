#ifndef BLOOM_FILTER_HPP
#define BLOOM_FILTER_HPP

#include <string>
#include <vector>

struct BloomFilter {
    std::vector<int> bits;
    size_t m;
    size_t k;
};

size_t bf_optimal_size(size_t v, size_t k);
BloomFilter bf_init(size_t m, size_t k);
size_t bf_hash(const std::string& s, size_t i, size_t m);
void bf_add(BloomFilter& bf, const std::string& s);
bool bf_check(const BloomFilter& bf, const std::string& s);

#endif
