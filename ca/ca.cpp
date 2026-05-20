#include "ca.hpp"
#include "../bloom_filter.hpp"
#include "../crypto/signature.hpp"

#include <sstream>

std::vector<unsigned char> serialize_encrypted_bf(
    const std::vector<mpz_class>& encrypted_bf
) {
    std::ostringstream oss;

    oss << encrypted_bf.size() << "\n";

    for (const auto& c : encrypted_bf) {
        oss << c.get_str(16) << "\n";
    }

    std::string s = oss.str();
    return std::vector<unsigned char>(s.begin(), s.end());
}

CertifiedEncryptedBF ca_certify_client_set(
    GM& gm,
    const GMPublicKey& pk,
    const std::vector<std::string>& client_set,
    size_t m,
    size_t k
) {
    BloomFilter bf = bf_init(m, k);

    for (const auto& item : client_set) {
        bf_add(bf, item);
    }

    std::vector<mpz_class> encrypted_bf;
    encrypted_bf.reserve(m);

    for (size_t i = 0; i < m; i++) {
        encrypted_bf.push_back(gm.encrypt_bit(pk, bf.bits[i]));
    }

    SignatureKeyPair ca_keys = generate_signature_keypair();

    std::vector<unsigned char> message =
        serialize_encrypted_bf(encrypted_bf);

    std::vector<unsigned char> signature =
        sign_message(ca_keys.private_pem, message);

    CertifiedEncryptedBF certified;
    certified.encrypted_bf = encrypted_bf;
    certified.signature = signature;
    certified.ca_public_key_pem = ca_keys.public_pem;

    return certified;
}

CertifiedEncryptedBF ca_certify_client_set_with_keys(
    GM& gm,
    const GMPublicKey& pk,
    const std::vector<std::string>& client_set,
    size_t m,
    size_t k,
    const SignatureKeyPair& ca_keys
) {
    BloomFilter bf = bf_init(m, k);

    for (const auto& item : client_set) {
        bf_add(bf, item);
    }

    std::vector<mpz_class> encrypted_bf;
    encrypted_bf.reserve(m);

    for (size_t i = 0; i < m; i++) {
        encrypted_bf.push_back(
            gm.encrypt_bit(pk, bf.bits[i])
        );
    }

    std::vector<unsigned char> message =
        serialize_encrypted_bf(encrypted_bf);

    std::vector<unsigned char> signature =
        sign_message(ca_keys.private_pem, message);

    CertifiedEncryptedBF cert;
    cert.encrypted_bf = encrypted_bf;
    cert.signature = signature;
    cert.ca_public_key_pem = ca_keys.public_pem;

    return cert;
}