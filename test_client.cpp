#include "gm.hpp"
#include "bloom_filter.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <cassert>

#define PASS(name) std::cout << "[PASS] " << name << "\n"
#define FAIL(name) std::cerr << "[FAIL] " << name << "\n"

static void test_bf_init() {
    BloomFilter bf = bf_init(100, 5);
    assert(bf.m == 100);
    assert(bf.k == 5);
    assert(bf.bits.size() == 100);
    for (int b : bf.bits) assert(b == 1);
    PASS("bf_init");
}

static void test_bf_hash_in_range() {
    size_t m = 500;
    for (size_t i = 0; i < 10; i++) {
        size_t idx = bf_hash("test_element", i, m);
        assert(idx < m);
    }
    PASS("bf_hash in range");
}

static void test_bf_hash_deterministic() {
    size_t a = bf_hash("hello", 3, 1000);
    size_t b = bf_hash("hello", 3, 1000);
    assert(a == b);
    PASS("bf_hash deterministic");
}

static void test_bf_hash_different_seeds() {
    size_t a = bf_hash("hello", 0, 1000);
    size_t b = bf_hash("hello", 1, 1000);
    assert(a != b);
    PASS("bf_hash different seeds produce different indices");
}

static void test_bf_add_and_check() {
    size_t m = bf_optimal_size(10, 5);
    BloomFilter bf = bf_init(m, 5);

    std::vector<std::string> elements = {"alice", "bob", "carol"};
    for (const auto& e : elements)
        bf_add(bf, e);

    for (const auto& e : elements)
        assert(bf_check(bf, e));

    // "dave" was not added — should (very likely) fail
    assert(!bf_check(bf, "dave_not_added_xyz123"));
    PASS("bf_add and bf_check");
}

static void test_build_and_encrypt_bf() {
    GM gm;
    GMPublicKey pk;
    GMSecretKey sk;
    gm.keygen(1024, pk, sk);

    std::vector<std::string> Y = {"alpha", "beta", "gamma"};
    size_t v = 50, k = 5;
    size_t m = bf_optimal_size(v, k);

    // build reference BF to compare against
    BloomFilter ref = bf_init(m, k);
    for (const auto& e : Y) bf_add(ref, e);

    // build and encrypt
    BloomFilter bf = bf_init(m, k);
    for (const auto& e : Y) bf_add(bf, e);

    std::vector<mpz_class> encrypted_bf;
    for (size_t i = 0; i < m; i++)
        encrypted_bf.push_back(gm.encrypt_bit(pk, bf.bits[i]));

    // decrypt and verify each bit matches
    for (size_t i = 0; i < m; i++) {
        int decrypted = gm.decrypt_bit(sk, encrypted_bf[i]);
        assert(decrypted == ref.bits[i]);
    }
    PASS("build_and_encrypt_bf");
}

int main() {
    test_bf_init();
    test_bf_hash_in_range();
    test_bf_hash_deterministic();
    test_bf_hash_different_seeds();
    test_bf_add_and_check();
    test_build_and_encrypt_bf();

    std::cout << "\nAll tests passed.\n";
    return 0;
}
