#ifndef NET_HPP
#define NET_HPP

#include <gmpxx.h>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#define PSI_PORT 9999
static const size_t K = 10;
// Write exactly n bytes, retrying on partial writes.
static void send_all(int fd, const void* buf, size_t n) {
    const char* p = static_cast<const char*>(buf);
    while (n > 0) {
        ssize_t sent = send(fd, p, n, 0);
        if (sent <= 0) throw std::runtime_error("send failed");
        p += sent;
        n -= sent;
    }
}

// Read exactly n bytes, retrying on partial reads.
static void recv_all(int fd, void* buf, size_t n) {
    char* p = static_cast<char*>(buf);
    while (n > 0) {
        ssize_t got = recv(fd, p, n, 0);
        if (got <= 0) throw std::runtime_error("recv failed");
        p += got;
        n -= got;
    }
}

// Send an mpz_class as a length-prefixed hex string.
static void send_mpz(int fd, const mpz_class& val) {
    std::string s = val.get_str(16);
    uint32_t len = static_cast<uint32_t>(s.size());
    send_all(fd, &len, sizeof(len));
    send_all(fd, s.data(), len);
}

// Receive an mpz_class encoded as a length-prefixed hex string.
static void recv_mpz(int fd, mpz_class& val) {
    uint32_t len = 0;
    recv_all(fd, &len, sizeof(len));
    std::string s(len, '\0');
    recv_all(fd, s.data(), len);
    val.set_str(s, 16);
}

#endif
