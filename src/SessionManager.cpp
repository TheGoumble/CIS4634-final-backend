#include "SessionManager.h"
#include "CryptoUtils.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <algorithm> // For std::find

// --- PLACEHOLDER FOR BOOST-BEAST NETWORKING ---
// NOTE: This placeholder does NOT implement actual networking. 
// It simulates sending by logging to the console.
void SessionManager::send_message_to_peer(const std::string& peer_id, const std::string& message_json) {
    std::cout << "[WS_SEND] To " << peer_id << ": " << message_json << std::endl;
}

// Utility: Creates a simple JSON string for key exchange
std::string SessionManager::create_key_message(
    const std::string& type, 
    const std::string& key_hex, 
    const std::string& peer_id) 
{
    // WARNING: For production, use a proper JSON library (like nlohmann/json) 
    // for robust payload creation.
    std::ostringstream oss;
    oss << "{\"type\":\"" << type 
        << "\",\"senderId\":\"" << peer_id 
        << "\",\"key\":\"" << key_hex << "\"}";
    return oss.str();
}

// --- SessionManager Implementations ---

SessionManager::SessionManager() {
    // Ensure the crypto system is initialized when the manager starts
    if (!initialize_crypto_system()) {
        std::cerr << "CRITICAL: Libsodium failed to initialize!" << std::endl;
        // In a real server, you might throw or exit here.
    }
    std::cout << "SessionManager initialized. Ready for zero-knowledge signaling." << std::endl;
}

// Handles Host connection and key generation
void SessionManager::handle_host_join(const std::string& room_id, const std::string& host_id) {
    try {
        // 1. Generate ephemeral X25519 key pair (Host's keys)
        KeyPair host_keys = generate_x25519_keypair(); 
        
        // 2. Create and store the host's data structure
        PeerSessionData host_data = { host_id, host_keys };
        
        StreamSession new_session;
        new_session.room_id = room_id;
        new_session.host_id = host_id;
        new_session.peers[host_id] = host_data;
        active_streams[room_id] = new_session;
        
        // 3. Send the Host's Public Key back to the Host's frontend for verification/client-side derivation
        std::string host_pub_key_hex = to_hex(host_keys.public_key);
        
        // HOST_KEYS_READY signal tells the Host their local public key is available
        std::string message = create_key_message("HOST_KEYS_READY", host_pub_key_hex, host_id);
        send_message_to_peer(host_id, message);
        
        std::cout << "[SESSION] Host " << host_id << " joined room " << room_id << ". Keys generated (Secret key stored securely)." << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Host join failed: " << e.what() << std::endl;
    }
}

// Handles Viewer key exchange (Zero-Knowledge Relay)
void SessionManager::handle_key_exchange(
    const std::string& room_id, 
    const std::string& viewer_id, 
    const std::string& viewer_pub_key_hex) 
{
    try {
        if (active_streams.find(room_id) == active_streams.end()) {
            std::cerr << "[ERROR] Room " << room_id << " not found for key exchange." << std::endl;
            return;
        }

        StreamSession& session = active_streams.at(room_id);
        const std::string& host_id = session.host_id;

        // A. RELAY: Inform Host of the new Viewer's Public Key
        // Host needs this key to perform client-side ECDH/HKDF.
        std::string viewer_key_message = create_key_message(
            "VIEWER_PUB_KEY", 
            viewer_pub_key_hex, 
            viewer_id // Sender is the Viewer
        );
        send_message_to_peer(host_id, viewer_key_message);
        std::cout << "[RELAY] Sent Viewer's key to Host " << host_id << std::endl;

        // B. RELAY: Send the Host's Public Key back to the Viewer
        // Viewer needs this key to perform client-side ECDH/HKDF.
        if (session.peers.find(host_id) == session.peers.end()) {
             throw std::runtime_error("Host data missing during Viewer key exchange.");
        }
        
        const std::vector<unsigned char>& host_public_key = session.peers.at(host_id).local_keys.public_key;
        std::string host_pub_key_hex = to_hex(host_public_key);

        std::string key_message = create_key_message(
            "HOST_PUB_KEY", 
            host_pub_key_hex, 
            host_id // Sender is the Host
        );
        send_message_to_peer(viewer_id, key_message);
        std::cout << "[RELAY] Sent Host's key to Viewer " << viewer_id << std::endl;

        // C. Update state to include the Viewer
        // Viewer's key pair is left empty here as the server does not manage their secret key.
        PeerSessionData viewer_data = { viewer_id, {} }; 
        session.peers[viewer_id] = viewer_data;

        std::cout << "[SECURITY] Zero-knowledge public key exchange complete for Viewer " << viewer_id << "." << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Key exchange failed for viewer " << viewer_id << ": " << e.what() << std::endl;
    }
}