#ifndef SIGNATURE_HPP
#define SIGNATURE_HPP

#include <string>
#include <vector>

struct SignatureKeyPair {
    std::string private_pem;
    std::string public_pem;
};

SignatureKeyPair generate_signature_keypair();

std::vector<unsigned char> sign_message(
    const std::string& private_pem,
    const std::vector<unsigned char>& message
);

bool verify_signature(
    const std::string& public_pem,
    const std::vector<unsigned char>& message,
    const std::vector<unsigned char>& signature
);

#endif