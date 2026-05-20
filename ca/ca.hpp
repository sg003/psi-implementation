#ifndef CA_HPP
#define CA_HPP

#include "../gm.hpp"
#include "../crypto/signature.hpp"
#include <gmpxx.h>
#include <string>
#include <vector>


struct CertifiedEncryptedBF {
    std::vector<mpz_class> encrypted_bf;
    std::vector<unsigned char> signature;
    std::string ca_public_key_pem;
};

CertifiedEncryptedBF ca_certify_client_set_with_keys(
    GM& gm,
    const GMPublicKey& pk,
    const std::vector<std::string>& client_set,
    size_t m,
    size_t k,
    const SignatureKeyPair& ca_keys
);

CertifiedEncryptedBF ca_certify_client_set(
    GM& gm,
    const GMPublicKey& pk,
    const std::vector<std::string>& client_set,
    size_t m,
    size_t k
);

std::vector<unsigned char> serialize_encrypted_bf(
    const std::vector<mpz_class>& encrypted_bf
);

#endif