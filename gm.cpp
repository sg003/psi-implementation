#include "gm.hpp"

#include <ctime>
#include <stdexcept>

GM::GM() : rng(gmp_randinit_default) {
    rng.seed(static_cast<unsigned long>(std::time(nullptr)));
}

mpz_class GM::generate_prime(unsigned int bits) {
    mpz_class candidate = rng.get_z_bits(bits);

    mpz_setbit(candidate.get_mpz_t(), bits - 1); // force correct bit length
    mpz_setbit(candidate.get_mpz_t(), 0);        // force odd

    mpz_nextprime(candidate.get_mpz_t(), candidate.get_mpz_t());

    return candidate;
}

mpz_class GM::random_coprime_mod_n(const mpz_class& n) {
    mpz_class r, gcd;

    do {
        r = rng.get_z_range(n);
        mpz_gcd(gcd.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t());
    } while (r == 0 || gcd != 1);

    return r;
}

int GM::legendre_symbol(const mpz_class& a, const mpz_class& p) {
    // Since p is prime, GMP's Jacobi symbol equals the Legendre symbol.
    return mpz_jacobi(a.get_mpz_t(), p.get_mpz_t());
}

mpz_class GM::find_pseudo_quadratic_residue(
    const mpz_class& p,
    const mpz_class& q,
    const mpz_class& n
) {
    mpz_class u, gcd;

    while (true) {
        u = rng.get_z_range(n);

        if (u <= 1) continue;

        mpz_gcd(gcd.get_mpz_t(), u.get_mpz_t(), n.get_mpz_t());
        if (gcd != 1) continue;

        int lp = legendre_symbol(u, p);
        int lq = legendre_symbol(u, q);
        int jn = mpz_jacobi(u.get_mpz_t(), n.get_mpz_t());

        if (lp == -1 && lq == -1 && jn == 1) {
            return u;
        }
    }
}

void GM::keygen(unsigned int modulus_bits, GMPublicKey& pk, GMSecretKey& sk) {
    if (modulus_bits < 1024) {
        throw std::runtime_error("Use at least 1024 bits. 2048 is better.");
    }

    unsigned int prime_bits = modulus_bits / 2;

    sk.p = generate_prime(prime_bits);

    do {
        sk.q = generate_prime(prime_bits);
    } while (sk.q == sk.p);

    pk.n = sk.p * sk.q;
    pk.u = find_pseudo_quadratic_residue(sk.p, sk.q, pk.n);
}

mpz_class GM::encrypt_bit(const GMPublicKey& pk, int bit) {
    if (bit != 0 && bit != 1) {
        throw std::runtime_error("GM encrypts only bits: 0 or 1.");
    }

    mpz_class r = random_coprime_mod_n(pk.n);
    mpz_class r_squared;

    mpz_powm_ui(
        r_squared.get_mpz_t(),
        r.get_mpz_t(),
        2,
        pk.n.get_mpz_t()
    );

    if (bit == 0) {
        return r_squared;
    }

    return (pk.u * r_squared) % pk.n;
}

int GM::decrypt_bit(const GMSecretKey& sk, const mpz_class& ciphertext) {
    mpz_class c_mod_p = ciphertext % sk.p;

    int value = legendre_symbol(c_mod_p, sk.p);

    if (value == 1) {
        return 0;
    }

    if (value == -1) {
        return 1;
    }

    throw std::runtime_error("Invalid ciphertext.");
}

mpz_class GM::homomorphic_xor(
    const GMPublicKey& pk,
    const mpz_class& c1,
    const mpz_class& c2
) {
    return (c1 * c2) % pk.n;
}

mpz_class GM::rerandomize(const GMPublicKey& pk, const mpz_class& c) {
    // c' = c * r^2 mod n
    // Same plaintext, fresh-looking ciphertext.
    mpz_class r = random_coprime_mod_n(pk.n);
    mpz_class r_squared;

    mpz_powm_ui(
        r_squared.get_mpz_t(),
        r.get_mpz_t(),
        2,
        pk.n.get_mpz_t()
    );

    return (c * r_squared) % pk.n;
}