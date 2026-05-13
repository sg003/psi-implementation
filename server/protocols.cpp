#include "../net.hpp"
#include "../gm.hpp"
#include "../bloom_filter.hpp"
#include "../ca/ca.hpp"
#include "../crypto/signature.hpp"

#include <iostream>
#include <vector>
#include <string>

std::vector<unsigned char> recv_bytes(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));

    std::vector<unsigned char> data(size);

    if (size > 0) {
        recv_all(fd, data.data(), size);
    }

    return data;
}

std::string recv_string(sock_t fd) {
    uint32_t size = 0;
    recv_all(fd, &size, sizeof(size));

    std::string s(size, '\0');

    if (size > 0) {
        recv_all(fd, s.data(), size);
    }

    return s;
}

std::vector<mpz_class> recv_encrypted_bf(sock_t fd) {
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));

    std::vector<mpz_class> encrypted_bf(m32);

    for (size_t i = 0; i < m32; i++) {
        recv_mpz(fd, encrypted_bf[i]);
    }

    return encrypted_bf;
}

void process_encrypted_bf_for_cardinality(
    sock_t fd,
    const std::vector<std::string>& X,
    const GMPublicKey& pk,
    const std::vector<mpz_class>& encrypted_bf
) {
    size_t m = encrypted_bf.size();
    GM gm;

    for (const auto& item : X) {
        for (size_t j = 0; j < K; j++) {
            size_t index = bf_hash(item, j, m);

            mpz_class rerandomized =
                gm.rerandomize(pk, encrypted_bf[index]);

            send_mpz(fd, rerandomized);
        }
    }
}

void server_psi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);

    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++) {
        recv_mpz(fd, encrypted_bf[i]);
    }

    GM gm;
    for (const auto& item : X) {
        for (size_t j = 0; j < K; j++) {
            size_t index = bf_hash(item, j, m);
            mpz_class rerandomized = gm.rerandomize(pk, encrypted_bf[index]);
            send_mpz(fd, rerandomized);
        }
    }
}

void server_psi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}

void server_apsi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    std::string ca_public_key_pem = recv_string(fd);

    std::vector<unsigned char> signature = recv_bytes(fd);

    std::vector<mpz_class> encrypted_bf = recv_encrypted_bf(fd);

    std::vector<unsigned char> message = serialize_encrypted_bf(encrypted_bf);

    bool valid = verify_signature(
        ca_public_key_pem,
        message,
        signature
    );

    if (!valid) {
        std::cerr << "APSI-CA signature verification failed. Aborting.\n";
        return;
    }

    std::cout << "APSI-CA signature verified." << std::endl;

    process_encrypted_bf_for_cardinality(
        fd,
        X,
        pk,
        encrypted_bf
    );
}

void server_apsi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {}