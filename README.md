# Two-Factor Authentication System with ZKP

A secure authentication system using trusted and untrusted devices with Zero-Knowledge Proofs.

## Features

- Two-factor authentication
- Zero-Knowledge Proofs for password verification
- Temporary login tokens
- Secure communication between devices and server

## Components

1. **Authentication Server** (server.c)
2. **Trusted Device** (trusted_device.c)
3. **Untrusted Device** (untrusted_device.c)

## Requirements

- GCC compiler
- OpenSSL library
- POSIX-compliant OS (Linux/Unix/macOS)

## Installation

1. Install OpenSSL:
sudo apt-get install libssl-dev # For Debian/Ubuntu
brew install openssl # For macOS

text

2. Compile the code:
gcc -o server server.c -lssl -lcrypto
gcc -o trusted_device trusted_device.c -lssl -lcrypto
gcc -o untrusted_device untrusted_device.c

text

## Usage

1. Start the server:
./server

text

2. Register a new account (on trusted device):
./trusted_device

Choose option 1, enter username and password
text

3. Login process:
- On trusted device:
  ```
  ./trusted_device
  # Choose option 2, enter credentials, note Token1
  ```
- On untrusted device:
  ```
  ./untrusted_device
  # Enter username and Token1
  ```
- Back on trusted device:
  - Confirm login, note Token2
- On untrusted device:
  - Enter Token2 to complete login

## Security Notes

- Keep the trusted device secure
- Don't share tokens between devices verbally or through insecure channels
- For educational purposes only, not for production use
