#include "gm.hpp"

#include <iostream>
#include <stdexcept>

int main() {
    try {
        GM gm;

        GMPublicKey pk;
        GMSecretKey sk;

        std::cout << "Generating keys...\n";
        gm.keygen(2048, pk, sk);
        std::cout << "Keys generated.\n\n";

        // BASIC ENCRYPTION / DECRYPTION

        for (int bit : {0, 1}) {
            mpz_class c = gm.encrypt_bit(pk, bit);

            std::cout << "Ciphertext for bit "
                      << bit << ":\n";

            std::cout << c << "\n\n";

            int decrypted = gm.decrypt_bit(sk, c);

            std::cout << "Decrypted value: "
                      << decrypted << "\n\n";

            if (decrypted != bit) {
                throw std::runtime_error(
                    "Encryption/decryption failed."
                );
            }
        }

        // RANDOMNESS TEST

        std::cout << "====================================\n";
        std::cout << "RANDOMNESS TEST\n";
        std::cout << "====================================\n\n";

        mpz_class c1 = gm.encrypt_bit(pk, 0);
        mpz_class c2 = gm.encrypt_bit(pk, 0);

        std::cout << "Encryption #1 of bit 0:\n";
        std::cout << c1 << "\n\n";

        std::cout << "Encryption #2 of bit 0:\n";
        std::cout << c2 << "\n\n";

        std::cout << "Are ciphertexts equal? "
                  << (c1 == c2 ? "YES" : "NO")
                  << "\n\n";

        // XOR HOMOMORPHISM TEST

        std::cout << "====================================\n";
        std::cout << "XOR HOMOMORPHISM TEST\n";
        std::cout << "====================================\n\n";

        for (int a : {0, 1}) {
            for (int b : {0, 1}) {

                mpz_class ca = gm.encrypt_bit(pk, a);
                mpz_class cb = gm.encrypt_bit(pk, b);

                mpz_class c_xor =
                    gm.homomorphic_xor(pk, ca, cb);

                int decrypted =
                    gm.decrypt_bit(sk, c_xor);

                std::cout << "a = " << a
                          << ", b = " << b << "\n\n";

                std::cout << "Enc(a):\n";
                std::cout << ca << "\n\n";

                std::cout << "Enc(b):\n";
                std::cout << cb << "\n\n";

                std::cout << "Enc(a) * Enc(b) mod n:\n";
                std::cout << c_xor << "\n\n";

                std::cout << "Decrypted result:\n";
                std::cout << decrypted << "\n";

                std::cout << "Expected XOR:\n";
                std::cout << (a ^ b) << "\n";

                std::cout << "\n--------------------------------\n\n";

                if (decrypted != (a ^ b)) {
                    throw std::runtime_error(
                        "XOR homomorphism failed."
                    );
                }
            }
        }

        // RERANDOMIZATION TEST

        std::cout << "====================================\n";
        std::cout << "RERANDOMIZATION TEST\n";
        std::cout << "====================================\n\n";

        mpz_class original =
            gm.encrypt_bit(pk, 1);

        mpz_class rerand =
            gm.rerandomize(pk, original);

        std::cout << "Original ciphertext:\n";
        std::cout << original << "\n\n";

        std::cout << "Rerandomized ciphertext:\n";
        std::cout << rerand << "\n\n";

        int before =
            gm.decrypt_bit(sk, original);

        int after =
            gm.decrypt_bit(sk, rerand);

        std::cout << "Before rerandomization decrypts to: "
                  << before << "\n";

        std::cout << "After rerandomization decrypts to:  "
                  << after << "\n\n";

        std::cout << "Ciphertexts equal? "
                  << (original == rerand ? "YES" : "NO")
                  << "\n\n";

        std::cout << "====================================\n";
        std::cout << "ALL TESTS PASSED\n";
        std::cout << "====================================\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Error: "
                  << e.what()
                  << "\n";

        return 1;
    }

    return 0;
}