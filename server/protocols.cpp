#include "../net.hpp"
#include "../gm.hpp"
#include "../bloom_filter.hpp"
#include "../ca/ca.hpp"
#include "../crypto/signature.hpp"

#include <iostream>
#include <vector>
#include <string>

static std::vector<mpz_class> xor_bf_with_phi(GM& gm, const GMPublicKey& pk,
    const std::vector<mpz_class>& encrypted_bf, const std::string& si, size_t m) {
    std::vector<mpz_class> result(K);
    for (size_t j = 0; j < K; j++) {
        size_t index = bf_hash(si, j, m);
        int phi = phi_bit(si, j);
        result[j] = phi
            ? gm.homomorphic_xor(pk, encrypted_bf[index], gm.encrypt_bit(pk, 1))
            : gm.rerandomize(pk, encrypted_bf[index]);
    }
    return result;
}

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

static bool verify_ca_certificate(
    const std::string& ca_public_key_pem,
    const std::vector<unsigned char>& signature,
    const std::vector<mpz_class>& encrypted_bf
) {
    std::vector<unsigned char> message = serialize_encrypted_bf(encrypted_bf);
    return verify_signature(ca_public_key_pem, message, signature);
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

void server_psi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);

    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++)
        recv_mpz(fd, encrypted_bf[i]);

    GM gm;
    for (const auto& si : X) {
        for (const auto& c : xor_bf_with_phi(gm, pk, encrypted_bf, si, m))
            send_mpz(fd, c);
    }
}

void server_apsi_ca(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    std::string ca_public_key_pem = recv_string(fd);

    std::vector<unsigned char> signature = recv_bytes(fd);

    std::vector<mpz_class> encrypted_bf = recv_encrypted_bf(fd);

    if (!verify_ca_certificate(ca_public_key_pem, signature, encrypted_bf)) {
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

void server_apsi(sock_t fd, const std::vector<std::string>& X, const GMPublicKey& pk, uint32_t v) {
    std::string ca_public_key_pem = recv_string(fd);

    std::vector<unsigned char> signature = recv_bytes(fd);

    uint32_t m32 = 0;
    recv_all(fd, &m32, sizeof(m32));
    size_t m = static_cast<size_t>(m32);

    std::vector<mpz_class> encrypted_bf(m);
    for (size_t i = 0; i < m; i++)
        recv_mpz(fd, encrypted_bf[i]);

    if (!verify_ca_certificate(ca_public_key_pem, signature, encrypted_bf)) {
        std::cerr << "APSI-CA signature verification failed. Aborting.\n";
        return;
    }

    std::cout << "APSI-CA signature verified." << std::endl;

    GM gm;
    for (const auto& raw_si : X) {
        // 1. Map the server's raw string into the exact same K-bit format as the client
        std::string s_kbit(K, '0');
        for (size_t j = 0; j < K; j++) {
            s_kbit[j] = '0' + phi_bit(raw_si, j);
        }

        std::vector<mpz_class> result(K);
        for (size_t j = 0; j < K; j++) {
            // 2. IMPORTANT: Use the K-bit string to find the Bloom Filter index!
            size_t index = bf_hash(s_kbit, j, m);
            
            // 3. The payload bit is simply the j-th character of our K-bit string
            int bit = s_kbit[j] - '0';
            
            // 4. Homomorphically multiply (XOR) the ciphertexts
            result[j] = gm.homomorphic_xor(pk, encrypted_bf[index], gm.encrypt_bit(pk, bit));
        }
        for (const auto& c : result)
            send_mpz(fd, c);
    }
}
