#include "signature.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdexcept>

static std::string bio_to_string(BIO* bio) {
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    return std::string(mem->data, mem->length);
}

SignatureKeyPair generate_signature_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        throw std::runtime_error("EVP_PKEY_keygen_init failed");

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0)
        throw std::runtime_error("setting RSA bits failed");

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
        throw std::runtime_error("EVP_PKEY_keygen failed");

    BIO* priv_bio = BIO_new(BIO_s_mem());
    BIO* pub_bio = BIO_new(BIO_s_mem());

    PEM_write_bio_PrivateKey(priv_bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_PUBKEY(pub_bio, pkey);

    SignatureKeyPair keys;
    keys.private_pem = bio_to_string(priv_bio);
    keys.public_pem = bio_to_string(pub_bio);

    BIO_free(priv_bio);
    BIO_free(pub_bio);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return keys;
}

std::vector<unsigned char> sign_message(
    const std::string& private_pem,
    const std::vector<unsigned char>& message
) {
    BIO* bio = BIO_new_mem_buf(private_pem.data(), private_pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) throw std::runtime_error("Could not read private key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
        throw std::runtime_error("DigestSignInit failed");

    if (EVP_DigestSignUpdate(ctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("DigestSignUpdate failed");

    size_t sig_len = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sig_len);

    std::vector<unsigned char> signature(sig_len);

    if (EVP_DigestSignFinal(ctx, signature.data(), &sig_len) <= 0)
        throw std::runtime_error("DigestSignFinal failed");

    signature.resize(sig_len);

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return signature;
}

bool verify_signature(
    const std::string& public_pem,
    const std::vector<unsigned char>& message,
    const std::vector<unsigned char>& signature
) {
    BIO* bio = BIO_new_mem_buf(public_pem.data(), public_pem.size());
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    if (!pkey) throw std::runtime_error("Could not read public key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) <= 0)
        throw std::runtime_error("DigestVerifyInit failed");

    if (EVP_DigestVerifyUpdate(ctx, message.data(), message.size()) <= 0)
        throw std::runtime_error("DigestVerifyUpdate failed");

    int ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ok == 1;
}