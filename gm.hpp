#ifndef GM_HPP
#define GM_HPP

#include <gmpxx.h>

struct GMPublicKey {
    mpz_class n;
    mpz_class u;
};

struct GMSecretKey {
    mpz_class p;
    mpz_class q;
};

class GM {
private:
    gmp_randclass rng;

    mpz_class generate_prime(unsigned int bits);
    mpz_class random_coprime_mod_n(const mpz_class& n);
    mpz_class find_pseudo_quadratic_residue(
        const mpz_class& p,
        const mpz_class& q,
        const mpz_class& n
    );

    int legendre_symbol(const mpz_class& a, const mpz_class& p);

public:
    GM();

    void keygen(unsigned int modulus_bits, GMPublicKey& pk, GMSecretKey& sk);

    mpz_class encrypt_bit(const GMPublicKey& pk, int bit);

    int decrypt_bit(const GMSecretKey& sk, const mpz_class& ciphertext);

    mpz_class homomorphic_xor(
        const GMPublicKey& pk,
        const mpz_class& c1,
        const mpz_class& c2
    );

    mpz_class rerandomize(const GMPublicKey& pk, const mpz_class& c);
};

#endif