#ifndef SESSION_MANAGER_H
#define SESSION_MANAGER_H

#include <string>
#include <map>
#include <vector>
#include "CryptoUtils.h" // Includes KeyPair struct and crypto functions

// --- Structures for State Management ---
struct PeerSessionData {
    std::string peer_id;
    // Stores the peer's X25519 public and secret key.
    // We only use the Host's secret key for server-side key storage/management.
    KeyPair local_keys; 
};

struct StreamSession {
    std::string room_id;
    std::string host_id;
    std::map<std::string, PeerSessionData> peers; // All participants
};

// --- SessionManager Class Definition ---
class SessionManager {
private:
    std::map<std::string, StreamSession> active_streams;
    
    // Placeholder for your actual WebSocket sender function (e.g., Boost.Beast)
    // The implementation relies on this being defined elsewhere.
    void send_message_to_peer(const std::string& peer_id, const std::string& message_json);

public:
    SessionManager();
    
    // Handles Host connection and key generation
    void handle_host_join(const std::string& room_id, const std::string& host_id);
    
    // Handles key exchange: relays the Viewer's key to the Host and the 
    // Host's key to the Viewer. NO KEY DERIVATION is performed here.
    void handle_key_exchange(
        const std::string& room_id, 
        const std::string& viewer_id, 
        const std::string& viewer_pub_key_hex
    );
    
    // Utility for creating key exchange messages (to send over WebSocket)
    std::string create_key_message(const std::string& type, const std::string& key_hex, const std::string& peer_id);
};

#endif // SESSION_MANAGER_H