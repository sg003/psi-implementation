#include "../net.hpp"
#include "ca.hpp"
#include "../gm.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#define CA_PORT 9001

static void send_string(sock_t fd, const std::string& s) {
    uint32_t size = static_cast<uint32_t>(s.size());
    send_all(fd, &size, sizeof(size));
    if (size > 0) send_all(fd, s.data(), size);
}

int main() {
    GM gm;

    SignatureKeyPair ca_keys = generate_signature_keypair();

    std::ofstream pub("ca_public.pem");
    pub << ca_keys.public_pem;
    pub.close();

    std::cout << "CA public key written to ca_public.pem\n";
    std::cout << "CA waiting on port " << CA_PORT << "...\n";

    sock_t server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(CA_PORT);

    if (bind(server_fd, (sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 1; }
    if (listen(server_fd, 1) < 0) { perror("listen"); return 1; }

    sock_t client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) { perror("accept"); return 1; }

    GMPublicKey pk;
    recv_mpz(client_fd, pk.n);
    recv_mpz(client_fd, pk.u);

    uint32_t m = 0;
    recv_all(client_fd, &m, sizeof(m));

    uint32_t y_size = 0;
    recv_all(client_fd, &y_size, sizeof(y_size));

    std::vector<std::string> Y;

    for (uint32_t i = 0; i < y_size; i++) {
        uint32_t len = 0;
        recv_all(client_fd, &len, sizeof(len));

        std::string item(len, '\0');
        recv_all(client_fd, item.data(), len);

        Y.push_back(item);
    }

    CertifiedEncryptedBF cert =
        ca_certify_client_set_with_keys(
            gm,
            pk,
            Y,
            m,
            K,
            ca_keys
        );

    uint32_t sig_size =
        static_cast<uint32_t>(cert.signature.size());

    send_all(client_fd, &sig_size, sizeof(sig_size));
    send_all(client_fd, cert.signature.data(), sig_size);

    uint32_t bf_size =
        static_cast<uint32_t>(cert.encrypted_bf.size());

    send_all(client_fd, &bf_size, sizeof(bf_size));

    for (const auto& c : cert.encrypted_bf) {
        send_mpz(client_fd, c);
    }

    send_string(client_fd, ca_keys.public_pem);

    std::cout << "CA certified encrypted BF and sent it to client.\n";

    CLOSE_SOCKET(client_fd);
    CLOSE_SOCKET(server_fd);

    return 0;
}
