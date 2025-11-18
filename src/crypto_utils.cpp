#include "crypto_utils.h"
#include <sodium.h>
#include <stdexcept>
#include <sstream>
#include <iomanip>

// --- Initialization ---

bool initialize_crypto_system() {
    // libsodium must be initialized once
    if (sodium_init() == -1) {
        // Handle error: libsodium failed to initialize
        return false;
    }
    return true;
}

// --- X25519 Key Generation ---

KeyPair generate_x25519_keypair() {
    KeyPair pair;
    // Set size according to libsodium constants for X25519
    pair.public_key.resize(crypto_box_PUBLICKEYBYTES);
    pair.secret_key.resize(crypto_box_SECRETKEYBYTES);

    if (crypto_box_keypair(pair.public_key.data(), pair.secret_key.data()) != 0) {
        throw std::runtime_error("X25519 key pair generation failed.");
    }
    return pair;
}

// --- X25519 ECDH (Raw Shared Secret Derivation) ---

std::vector<unsigned char> derive_raw_shared_secret(
    const std::vector<unsigned char>& local_secret_key,
    const std::vector<unsigned char>& remote_public_key) {

    if (local_secret_key.size() != crypto_box_SECRETKEYBYTES || 
        remote_public_key.size() != crypto_box_PUBLICKEYBYTES) {
        throw std::invalid_argument("Invalid key size for ECDH derivation.");
    }

    std::vector<unsigned char> raw_shared_secret(crypto_box_BEFORENMBYTES);

    // crypto_scalarmult is the core X25519 ECDH operation
    if (crypto_scalarmult(
        raw_shared_secret.data(), 
        local_secret_key.data(), 
        remote_public_key.data()
    ) != 0) {
        throw std::runtime_error("X25519 shared secret computation failed.");
    }
    
    return raw_shared_secret;
}

// --- HKDF-SHA256 (Final Session Key Derivation) ---

std::vector<unsigned char> derive_aes_session_key(
    const std::vector<unsigned char>& raw_shared_secret,
    const std::string& info) {

    std::vector<unsigned char> session_key(AES_SESSION_KEY_SIZE);

    // crypto_kdf_derive_from_key uses HKDF internally
    // IKM = raw_shared_secret
    // Info = info string
    if (crypto_kdf_derive_from_key(
        session_key.data(),           // Output key buffer
        AES_SESSION_KEY_SIZE,         // Output key size (32 bytes)
        1,                            // Subkey index (typically 1 for the first key)
        info.c_str(),                 // Contextual info for HKDF
        raw_shared_secret.data()      // Input Key Material (IKM)
    ) != 0) {
        throw std::runtime_error("HKDF-SHA256 key derivation failed.");
    }

    return session_key;
}

// --- Utility Functions (Hex conversion for signaling) ---

std::string to_hex(const std::vector<unsigned char>& data) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto& byte : data) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> from_hex(const std::string& hex_string) {
    if (hex_string.length() % 2 != 0) {
        throw std::invalid_argument("Hex string length must be even.");
    }

    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex_string.length(); i += 2) {
        std::string byte_string = hex_string.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byte_string, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}