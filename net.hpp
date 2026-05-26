#ifndef NET_HPP
#define NET_HPP

#include "config.hpp"
#include <gmpxx.h>
#include <cstdint>
#include <stdexcept>
#include <string>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET sock_t;
  #define CLOSE_SOCKET closesocket
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  typedef int sock_t;
  #define CLOSE_SOCKET close
#endif


static void send_all(sock_t fd, const void* buf, size_t n) {
    const char* p = static_cast<const char*>(buf);
    while (n > 0) {
        int sent = send(fd, p, static_cast<int>(n), 0);
        if (sent <= 0) throw std::runtime_error("send failed");
        p += sent;
        n -= sent;
    }
}

static void recv_all(sock_t fd, void* buf, size_t n) {
    char* p = static_cast<char*>(buf);
    while (n > 0) {
        int got = recv(fd, p, static_cast<int>(n), 0);
        if (got <= 0) throw std::runtime_error("recv failed");
        p += got;
        n -= got;
    }
}

static void send_mpz(sock_t fd, const mpz_class& val) {
    std::string s = val.get_str(16);
    uint32_t len = static_cast<uint32_t>(s.size());
    send_all(fd, &len, sizeof(len));
    send_all(fd, s.data(), len);
}

static void recv_mpz(sock_t fd, mpz_class& val) {
    uint32_t len = 0;
    recv_all(fd, &len, sizeof(len));
    std::string s(len, '\0');
    recv_all(fd, s.data(), len);
    val.set_str(s, 16);
}

// Bytes consumed on the wire by send_mpz/recv_mpz for a given value.
static size_t mpz_wire_bytes(const mpz_class& val) {
    return sizeof(uint32_t) + val.get_str(16).size();
}

#endif
