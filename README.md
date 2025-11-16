# Secure Signaling Server
### Team members:
Brittany Krutchik, Ty Larson, Javier Vargas

## Abstract
This project is a high-performance C++ WebSocket signaling server designed to manage real-time communication sessions between clients (e.g., frontend applications for media, chat, and control). It features a custom, standards-based cryptographic implementation to secure all communication channels. The server handles the initial X25519 Key Exchange and subsequent ChaCha20-Poly1305 authenticated encryption to derive and manage unique, ephemeral session keys for the distinct Media, Chat, and Control channels. This backend provides a secure foundation for real-time, peer-to-peer applications


## Prerequisites
- IDE: Visual Studio (Recommended for Windows) or VS Code with C++ extensions.

## Set Up & Build
1. Copy and paste this command in the command line to download the repo
```bash
PC $ git clone https://github.com/TheGoumble/CIS4634-final-backend.git
```
2. Build the Soluction
```bash
PC $ CIS4634-final-backend/GENERATE_SLN.bat
```

## Run and Test
After the bat file is executed a builds folder will populate
```bash
PC $ cd CIS4634-final-backend/build
```

## Adding new packages 
Files requiring updates

vcpkg.json
```bash
 "dependencies": [
        "*package name*"
    ]
```

CMakeLists.txt
```bash
# Add package
find_package(*package name* CONFIG REQUIRED)

# Automatically links to these libs
target_link_libraries(Playground PRIVATE
    *package*::*package*
)
```
running the bat file again should apply the new packages to the project

video on environment set up

https://www.youtube.com/watch?v=PzRGsH3dOqI
