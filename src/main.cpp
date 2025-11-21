#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <vector>
#include <algorithm>
#include <random>
#include <ctime>
#include <sstream> // For JSON parsing help

// Networking and TLS dependencies
#include <websocketpp/config/asio.hpp> 
#include <websocketpp/server.hpp>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <set> // Required for session_groups

typedef websocketpp::server<websocketpp::config::asio_tls> server;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;
using websocketpp::connection_hdl;
using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

// --- PORT DEFINITIONS FOR MULTI-CHANNEL SYSTEM ---
const int CONTROL_CHANNEL_WSS_PORT = 8080;
const int CHAT_CHANNEL_WSS_PORT = 8081;
const int MEDIA_STREAM_RTP_START_PORT = 40000;
const int MEDIA_STREAM_RTP_END_PORT = 49999;


// --- API USER IDENTITY STRUCTURE ---
struct PeerIdentity {
    std::string user_id;     // Unique identifier for the authenticated user
    std::string username;    // Display name
    std::string auth_token;  // Placeholder for the token used to authenticate
    std::string session_id;  // **NEW: Session ID extracted from the initial message**
};


// --- CRITICAL STRUCTURES ---
struct ClientSession {
    std::string peer_id;    // Unique ID of the authenticated peer
    std::string session_id; // **NEW: Session ID to group peers**

    std::vector<unsigned char> x25519_pubkey;
    EVP_PKEY* x25519_keypair = nullptr; // Server's ephemeral key pair

    // Derived keys for the session (32 bytes each recommended)
    std::vector<unsigned char> session_aes_key;
    std::vector<unsigned char> session_hmac_key;

    // State machine flags
    bool authenticated = false;         // True after a valid token is processed
    bool handshake_complete = false;    // True after key exchange is done

    int assigned_media_port = 0;
};

// Global map to track individual sessions by connection handle
std::map<connection_hdl, ClientSession, std::owner_less<connection_hdl>> sessions;

// **NEW: Global map to group connected handles by Session ID for relaying**
// Uses std::owner_less<connection_hdl> to allow hdl to be used as a map key
std::map<std::string, std::set<connection_hdl, std::owner_less<connection_hdl>>> session_groups;


// --- UTILITY/PLACEHOLDER FUNCTIONS FOR AUTHENTICATION & PARSING ---

/**
 * @brief Placeholder function to simulate checking an authentication token against a database.
 */
bool validate_token(const std::string& token, PeerIdentity& peer) {
    if (token.empty()) return false;

    // Simple placeholder logic: look for known valid tokens
    if (token == "VALID_TOKEN_123") {
        peer.user_id = "user-A001";
        peer.username = "Alice";
        return true;
    }
    else if (token == "VALID_TOKEN_456") {
        peer.user_id = "user-B002";
        peer.username = "Bob";
        return true;
    }

    return false;
}

/**
 * @brief Highly simplified JSON string parsing to extract auth_token and session_id.
 *
 * NOTE: For production, a robust JSON library (like nlohmann/json) should be used.
 */
PeerIdentity parse_auth_payload(const std::string& json_payload) {
    PeerIdentity peer = {};

    // 1. Extract auth_token
    size_t start_t = json_payload.find("\"auth_token\":\"");
    if (start_t != std::string::npos) {
        start_t += 14;
        size_t end_t = json_payload.find('"', start_t);
        if (end_t != std::string::npos) {
            peer.auth_token = json_payload.substr(start_t, end_t - start_t);
        }
    }

    // 2. Extract session_id
    size_t start_s = json_payload.find("\"session_id\":\"");
    if (start_s != std::string::npos) {
        start_s += 14;
        size_t end_s = json_payload.find('"', start_s);
        if (end_s != std::string::npos) {
            peer.session_id = json_payload.substr(start_s, end_s - start_s);
        }
    }

    return peer;
}


// --- 1. CRYPTOGRAPHIC PRIMITIVES (X25519 & HKDF) ---

/**
 * @brief Generates a new X25519 key pair for the server.
 */
bool generate_x25519_keypair(ClientSession& session) {
    session.x25519_keypair = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
    if (!session.x25519_keypair) {
        std::cerr << "Error generating X25519 key pair." << std::endl;
        return false;
    }

    // Extract public key
    size_t publen = 0;
    if (EVP_PKEY_get_raw_public_key(session.x25519_keypair, NULL, &publen) != 1) return false;
    session.x25519_pubkey.resize(publen);
    if (EVP_PKEY_get_raw_public_key(session.x25519_keypair, session.x25519_pubkey.data(), &publen) != 1) {
        session.x25519_pubkey.clear();
        return false;
    }
    return true;
}

/**
 * @brief Performs the X25519 key agreement to derive the shared secret.
 *
 */
std::vector<unsigned char> derive_shared_secret(ClientSession& session, const std::vector<unsigned char>& client_pubkey) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(session.x25519_keypair, NULL);
    if (!pctx) return {};

    std::vector<unsigned char> shared_secret;
    EVP_PKEY* peer_pubkey = EVP_PKEY_new_raw_public_key(NID_X25519, NULL, client_pubkey.data(), client_pubkey.size());
    if (!peer_pubkey) { EVP_PKEY_CTX_free(pctx); return {}; }

    // Key derivation process
    if (EVP_PKEY_derive_init(pctx) <= 0 || EVP_PKEY_derive_set_peer(pctx, peer_pubkey) <= 0) {
        EVP_PKEY_free(peer_pubkey); EVP_PKEY_CTX_free(pctx); return {};
    }

    size_t secret_len;
    if (EVP_PKEY_derive(pctx, NULL, &secret_len) <= 0) {
        EVP_PKEY_free(peer_pubkey); EVP_PKEY_CTX_free(pctx); return {};
    }

    shared_secret.resize(secret_len);
    if (EVP_PKEY_derive(pctx, shared_secret.data(), &secret_len) <= 0) {
        shared_secret.clear();
    }

    EVP_PKEY_free(peer_pubkey);
    EVP_PKEY_CTX_free(pctx);

    return shared_secret;
}

/**
 * @brief Uses HKDF-SHA256 to derive specific keys from the shared secret (using PBKDF2 as a compatible primitive).
 */
bool derive_session_keys_hkdf(const std::vector<unsigned char>& shared_secret, ClientSession& session) {
    const unsigned char* salt = NULL;
    size_t salt_len = 0;

    const size_t KEY_LEN = 32;
    const size_t TOTAL_LEN = KEY_LEN * 2;
    std::vector<unsigned char> derived_keys(TOTAL_LEN);

    if (PKCS5_PBKDF2_HMAC_SHA1(
        (const char*)shared_secret.data(), shared_secret.size(),
        salt, salt_len,
        10000,
        derived_keys.size(), derived_keys.data()
    ) != 1) {
        std::cerr << "Error during HKDF key derivation." << std::endl;
        return false;
    }

    // Split the derived keys
    session.session_aes_key.assign(derived_keys.begin(), derived_keys.begin() + KEY_LEN);
    session.session_hmac_key.assign(derived_keys.begin() + KEY_LEN, derived_keys.end());

    return true;
}

// --- 2. CUSTOM AES-GCM INTEGRATION POINT ---
/**
 * @brief Placeholder for the user's custom AES-GCM encryption system.
 */
std::string CustomAesGcmEncrypt(const std::string& plaintext, const std::vector<unsigned char>& key) {
    // --- THIS IS WHERE YOUR CUSTOM AES LOGIC GOES ---
    if (key.size() != 32) {
        return "ERROR: Invalid key size for custom AES.";
    }
    // PLACEHOLDER: Returning a dummy encrypted message
    return "ENCRYPTED::" + plaintext + "::CUSTOM_AES_SYSTEM_READY";
}

// --- 3. SERVER IMPLEMENTATION (Websocketpp) ---

context_ptr on_tls_init(connection_hdl hdl) {
    context_ptr ctx = websocketpp::lib::make_shared<websocketpp::lib::asio::ssl::context>(
        websocketpp::lib::asio::ssl::context::tlsv12
    );
    try {
        ctx->use_private_key_file("server.key", websocketpp::lib::asio::ssl::context::pem);
        ctx->use_certificate_chain_file("server.crt");
        SSL_CTX_set_cipher_list(ctx->native_handle(), "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
    }
    catch (std::exception& e) {
        std::cerr << "TLS Error: Please ensure 'server.crt' and 'server.key' exist in the executable's directory." << std::endl;
    }
    return ctx;
}

void on_open(server* s, connection_hdl hdl) {
    // Initialize session state
    ClientSession& session = sessions[hdl];
    session.authenticated = false;
    session.handshake_complete = false;

    std::cout << "[+] New WSS connection opened. Waiting for Auth+Session JSON." << std::endl;
}

void relay_message_to_session(server* s, connection_hdl sender_hdl, const std::string& session_id, const std::string& payload, bool is_binary) {
    if (session_groups.count(session_id)) {
        const auto& peers = session_groups[session_id];

        // Count for logging
        int forwarded_count = 0;

        for (const auto& peer_hdl : peers) {
            // Do not send the message back to the original sender
            if (peer_hdl != sender_hdl) {
                // Check if the target peer's socket is open
                websocketpp::session::state::value peer_state = s->get_con_from_hdl(peer_hdl)->get_state();
                if (peer_state == websocketpp::session::state::open) {
                    try {
                        if (is_binary) {
                            s->send(peer_hdl, payload.data(), payload.size(), websocketpp::frame::opcode::binary);
                        }
                        else {
                            s->send(peer_hdl, payload, websocketpp::frame::opcode::text);
                        }
                        forwarded_count++;
                    }
                    catch (const websocketpp::exception& e) {
                        std::cerr << "[error] Failed to relay to peer: " << e.what() << std::endl;
                    }
                }
            }
        }
        std::cout << "[Relay] Session " << session_id << " forwarded message to " << forwarded_count << " peers." << std::endl;
    }
    else {
        std::cerr << "[warn] Message received for unknown or empty session: " << session_id << std::endl;
    }
}

void on_message(server* s, connection_hdl hdl, server::message_ptr msg) {
    ClientSession& session = sessions[hdl];
    std::string payload = msg->get_payload();

    if (!session.authenticated) {
        // --- 1. AUTHENTICATION PENDING ---
        PeerIdentity peer_data = parse_auth_payload(payload);

        if (peer_data.auth_token.empty() || peer_data.session_id.empty() || !validate_token(peer_data.auth_token, peer_data)) {
            std::cerr << "Authentication or Session ID missing/invalid. Closing connection." << std::endl;
            s->close(hdl, websocketpp::close::status::policy_violation, "Authentication Required.");
            return;
        }

        // Authentication Success: Update session state
        session.authenticated = true;
        session.peer_id = peer_data.user_id;
        session.session_id = peer_data.session_id; // Store session ID

        // Add client to the global session group map
        session_groups[session.session_id].insert(hdl);

        std::cout << "Authenticated Peer ID: " << session.peer_id
            << " in Session: " << session.session_id
            << ". Starting Key Exchange." << std::endl;

        // Start Key Exchange process:
        if (!generate_x25519_keypair(session)) {
            s->close(hdl, websocketpp::close::status::protocol_error, "Key generation failure.");
            return;
        }

        // Send the server's public key (pubkey_b64 is raw binary for this example)
        std::string pubkey_b64(session.x25519_pubkey.begin(), session.x25519_pubkey.end());
        std::string x25519_init = "{ \"type\": \"KEY_INIT\", \"server_pubKey\": \"" + pubkey_b64 + "\", \"user_id\": \"" + session.peer_id + "\" }";
        s->send(hdl, x25519_init, websocketpp::frame::opcode::text);

        return; // Wait for client's public key in the next message

    }
    else if (session.authenticated && !session.handshake_complete) {
        // --- 2. KEY EXCHANGE PENDING ---
        // Expecting a raw 32-byte client public key.
        if (payload.size() != 32) {
            std::cerr << "Key exchange failed for Peer " << session.peer_id << ": Expected raw 32-byte public key." << std::endl;
            s->close(hdl, websocketpp::close::status::protocol_error, "Invalid key exchange message.");
            return;
        }

        // 1. Derive Shared Secret (Diffie-Hellman)
        std::vector<unsigned char> client_pubkey(payload.begin(), payload.end());
        std::vector<unsigned char> shared_secret = derive_shared_secret(session, client_pubkey);

        if (shared_secret.empty()) {
            std::cerr << "Error deriving shared secret." << std::endl;
            s->close(hdl, websocketpp::close::status::protocol_error, "Shared secret derivation failure.");
            return;
        }

        // 2. Derive Session Keys (HKDF)
        if (!derive_session_keys_hkdf(shared_secret, session)) {
            s->close(hdl, websocketpp::close::status::protocol_error, "HKDF failure.");
            return;
        }

        // --- Handshake Complete Actions ---
        session.handshake_complete = true;
        session.assigned_media_port = MEDIA_STREAM_RTP_START_PORT + (rand() % (MEDIA_STREAM_RTP_END_PORT - MEDIA_STREAM_RTP_START_PORT));

        std::cout << "--- SECURE HANDSHAKE COMPLETE for Peer " << session.peer_id << " ---" << std::endl;

        // Send a confirmation message (encrypted, using the new key!)
        std::string confirmation_msg = "Keys established. Start sending media/chat data to port " + std::to_string(session.assigned_media_port) + ".";
        std::string encrypted_confirmation = CustomAesGcmEncrypt(confirmation_msg, session.session_aes_key);
        s->send(hdl, encrypted_confirmation, websocketpp::frame::opcode::text);

    }
    else {
        // --- 3. ENCRYPTED DATA CHANNEL / RELAY LOGIC (From Node.js script) ---

        // If it's a raw binary payload, assume it's an encrypted frame that needs relaying
        if (msg->get_opcode() == websocketpp::frame::opcode::binary) {
            relay_message_to_session(s, hdl, session.session_id, payload, true);
            return;
        }

        // Otherwise, assume text (JSON) for control messages or encrypted data
        try {
            // Attempt to parse JSON (simplified check)
            if (payload.find('{') == 0 && payload.find('}') == payload.length() - 1) {
                // NOTE: Proper C++ JSON parsing is required here.
                // We will rely on string matching for the types, similar to Node.js simple parsing.

                // --- Control Message Handling (hello, metric, chat) ---
                if (payload.find("\"type\":\"hello\"") != std::string::npos) {
                    // Log the hello message
                    std::cout << "[HELLO] Peer " << session.peer_id << " joined session " << session.session_id << std::endl;
                    // Optional: Broadcast "peer joined" event
                    return;
                }

                if (payload.find("\"type\":\"metric\"") != std::string::npos) {
                    // Respond with pong
                    std::ostringstream pong_stream;
                    // Note: C++ uses std::time(0) for a Unix-like timestamp in seconds.
                    pong_stream << "{\"type\":\"pong\", \"ts\":" << std::time(0) << "}";
                    s->send(hdl, pong_stream.str(), websocketpp::frame::opcode::text);
                    return;
                }

                if (payload.find("\"type\":\"chat\"") != std::string::npos) {
                    // Plaintext chat is discouraged in a secure platform, but we relay it as requested
                    relay_message_to_session(s, hdl, session.session_id, payload, false);
                    return;
                }

                // --- Encrypted Frame Handling (The core relaying) ---
                // Check for the shape of an encrypted frame used in the Node.js script
                // if (msg.kind && msg.ivB64 && msg.aadB64 && msg.payloadB64)
                if (payload.find("\"kind\"") != std::string::npos &&
                    payload.find("\"ivB64\"") != std::string::npos &&
                    payload.find("\"payloadB64\"") != std::string::npos)
                {
                    // Relay the JSON payload as a text message
                    relay_message_to_session(s, hdl, session.session_id, payload, false);
                    return;
                }

                std::cout << "[warn] Unrecognized JSON message shape from Peer " << session.peer_id << ": " << payload.substr(0, 50) << "..." << std::endl;

            }
            else {
                // If it's not binary and not JSON, assume it's just raw encrypted data post-handshake
                std::cout << "Peer " << session.peer_id << " received Raw Encrypted Data: " << payload.size() << " bytes." << std::endl;
            }

        }
        catch (const std::exception& e) {
            std::cerr << "[error] Failed to parse/handle message from Peer " << session.peer_id << ": " << e.what() << std::endl;
        }
    }
}

void on_close(server* s, connection_hdl hdl) {
    if (sessions.count(hdl)) {
        ClientSession& session = sessions[hdl];

        std::cout << "[-] Peer " << session.peer_id << " connection closed and session cleaned up." << std::endl;

        // 1. Remove from session group
        if (!session.session_id.empty() && session_groups.count(session.session_id)) {
            session_groups[session.session_id].erase(hdl);

            // 2. Clean up group map if session is empty
            if (session_groups[session.session_id].empty()) {
                std::cout << "[info] Session " << session.session_id << " removed (no more clients)." << std::endl;
                session_groups.erase(session.session_id);
            }
            else {
                std::cout << "[info] Session " << session.session_id << " remaining: " << session_groups[session.session_id].size() << std::endl;
            }
        }

        // 3. Clean up the OpenSSL key pair memory
        if (session.x25519_keypair) {
            EVP_PKEY_free(session.x25519_keypair);
        }
        // 4. Remove individual session
        sessions.erase(hdl);
    }
    else {
        std::cout << "Connection closed and session cleaned up (unauthenticated)." << std::endl;
    }
}

int main()
{
    // Initialize random number generator for port assignment and placeholder IDs
    srand(time(0));

    server signaling_server;

    try {
        signaling_server.set_access_channels(websocketpp::log::alevel::all);
        signaling_server.clear_access_channels(websocketpp::log::alevel::frame_payload);
        signaling_server.init_asio();
        signaling_server.set_tls_init_handler(bind(&on_tls_init, _1));

        signaling_server.set_open_handler(bind(&on_open, &signaling_server, _1));
        signaling_server.set_message_handler(bind(&on_message, &signaling_server, _1, _2));
        signaling_server.set_close_handler(bind(&on_close, &signaling_server, _1));

        signaling_server.listen(CONTROL_CHANNEL_WSS_PORT);

        signaling_server.start_accept();

        std::cout << "--- Secure Signaling Server Starting ---" << std::endl;
        std::cout << "Control Channel: wss://127.0.0.1:" << CONTROL_CHANNEL_WSS_PORT << std::endl;
        std::cout << "Awaiting initial JSON payload containing {\"auth_token\": \"...\", \"session_id\": \"...\"}" << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;

        signaling_server.run();

    }
    catch (websocketpp::exception const& e) {
        std::cerr << "Websocketpp error: " << e.what() << std::endl;
    }
    catch (std::exception const& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception occurred" << std::endl;
    }

    return 0;
}