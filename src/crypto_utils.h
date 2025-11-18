#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <vector>
#include <string>

// Define key sizes based on Libsodium's X25519 constants
// crypto_box uses X25519 key exchange
constexpr size_t KEY_SIZE = 32; // 32 bytes for Public/Secret keys
constexpr size_t AES_SESSION_KEY_SIZE = 32; // Final AES-256 key size

// Structure to hold a standard X25519 key pair
struct KeyPair {
    std::vector<unsigned char> public_key;
    std::vector<unsigned char> secret_key;
};

// Initializes the Libsodium library (must be called once at startup)
bool initialize_crypto_system();

// Generates a new X25519 key pair (for the peer)
KeyPair generate_x25519_keypair();

// Derives a raw shared secret (32 bytes) from the local secret key and the remote public key.
// This is the core X25519 ECDH step.
std::vector<unsigned char> derive_raw_shared_secret(
    const std::vector<unsigned char>& local_secret_key,
    const std::vector<unsigned char>& remote_public_key);

// Key Derivation Function (HKDF-SHA256) 
// Uses the raw shared secret (IKM) to derive the final, unique AES session key.
// 'info' provides context for the session (e.g., "stream-session-v1").
std::vector<unsigned char> derive_aes_session_key(
    const std::vector<unsigned char>& raw_shared_secret,
    const std::string& info);

// Converts a byte vector to a hexadecimal string for safe transmission/logging
std::string to_hex(const std::vector<unsigned char>& data);

// Converts a hexadecimal string back to a byte vector
std::vector<unsigned char> from_hex(const std::string& hex_string);

#endif // CRYPTO_UTILS_H