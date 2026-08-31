# EFSS

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=for-the-badge&logo=go" alt="Go" />
  <img src="https://img.shields.io/badge/PostgreSQL-16-336791?style=for-the-badge&logo=postgresql" alt="PostgreSQL" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker" alt="Docker Compose" />
  <img src="https://img.shields.io/badge/Status-Exam%20Project-1E3A8A?style=for-the-badge" alt="Exam project" />
</p>

<p align="center">
  <strong>Encrypted File Sharing System</strong>
</p>

<h3 align="center">
  A secure file-sharing prototype developed for the final exam of <em>"Sicurezza dell'informazione M"</em> at the University of Bologna (Unibo)
</h3>

EFSS is a proof-of-concept system for encrypted file exchange between users. It combines modern cryptographic primitives with a lightweight client/server architecture to demonstrate the practical application of confidentiality, integrity, authentication, and access control in a file distribution workflow.

## Overview

The project implements a secure mailbox-like file-sharing workflow where each user can:

- register with a username and password
- generate a public/private keypair locally
- upload encrypted files for one or more recipients
- receive encrypted messages in an inbox
- decrypt files only with their own private key
- verify digital signatures from the sender

This solution was designed as an academic project for the final exam of the course "Sicurezza dell'informazione M" at Unibo, with a strong focus on cryptographic engineering and secure-by-design implementation.

## Why this project

The goal of EFSS is to model a realistic encrypted file-sharing system while keeping the design simple enough to be understandable and demonstrable. The focus is on applying core information security concepts in a working implementation:

- confidentiality through symmetric encryption and RSA key wrapping
- integrity and authenticity through RSA-PSS signatures
- secure password handling through Argon2id
- protection of private keys with password-based encryption
- authenticated sessions and protected API access
- persistent storage for users, sessions, and encrypted messages

## Architecture

The system is composed of two main parts:

- a Go-based backend API server
- a Go CLI client that handles cryptographic operations and authenticated communication

The backend stores user information, sessions, and message metadata in PostgreSQL. The client is responsible for generating keys, encrypting files, verifying signatures, and managing the mailbox workflow.

## Core features

- User registration and login with salted password hashing
- Argon2id-based derivation for encrypted private key protection
- RSA 4096 key generation for user identities
- AES-256-GCM encryption for file payload confidentiality
- RSA-OAEP wrapping for secure symmetric key exchange between users
- RSA-PSS digital signatures for sender authenticity and integrity
- Secure inbox with per-recipient encrypted messages
- Message delivery tracking and retrieval by recipient
- Dockerized PostgreSQL + backend deployment
- CLI commands for secure file encryption, signing, verification, and transfer

## Security model

EFSS applies the following security measures:

- Passwords are hashed with Argon2id using a unique salt per user
- Private keys are encrypted locally with a password-derived AES key
- Symmetric file keys are generated randomly and encrypted with the recipient public key using RSA-OAEP
- Files are encrypted with AES-GCM, ensuring confidentiality and tamper detection
- Signatures are created with RSA-PSS over the encrypted payload to guarantee sender authenticity and content integrity
- Backend API access is protected by session tokens associated with authenticated users
- Database storage contains encrypted payloads and protected metadata, not plaintext shared content

## Tech stack

- Go 1.25+
- PostgreSQL 16
- Docker + Docker Compose
- Cobra CLI framework
- X/crypto libraries for Argon2, AES-GCM, RSA, and secure key handling

## Repository structure

```text
.
├── .env.example
├── docker-compose.yaml
├── LICENSE
├── README.md
├── client/
│   ├── cmd/
│   ├── config/
│   ├── crypto/
│   ├── api/
│   ├── main.go
│   ├── go.mod
│   └── go.sum
├── server/
│   ├── db/
│   ├── handlers/
│   ├── middleware/
│   ├── main.go
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
└── .gitignore
```

## Installation

### Prerequisites

Make sure you have the following installed:

- Go 1.25 or newer
- Docker Desktop or Docker Engine with Compose
- Git

### 1) Clone the repository

```bash
git clone https://github.com/pierror404/EFSS.git
cd EFSS
```

### 2) Configure environment variables

Copy the example environment file and adjust the values for your local setup:

```bash
cp .env.example .env
```

Then edit `.env` as needed, for example:

```env
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_strong_password
POSTGRES_DB=efss
DATABASE_URL=postgres://postgres:your_strong_password@db:5432/efss?sslmode=disable
```

### 3) Start the infrastructure

From the project root:

```bash
docker compose up --build -d
```

This starts:

- PostgreSQL on port 5432
- the EFSS backend on port 8080

### 4) Build the CLI client

Build the client binary from the `client` folder:

```bash
cd client
go build -o efss .
```

The generated binary is ready to use from the project directory.

## Getting started

### Register a user

```bash
./efss register alice
```

The CLI will prompt for a password and generate a local keypair under the default configuration directory (`~/.efss/keys`).

### Log in

```bash
./efss login alice
```

### Send a file

```bash
./efss send report.pdf --to bob
```

This command encrypts the file, signs it with the sender's private key, and sends it to the chosen recipient(s).

### Check inbox

```bash
./efss inbox
```

### Receive a message

```bash
./efss receive 1 --output recovered.pdf
```

The CLI downloads the encrypted message, unwraps the symmetric key using the local private key, verifies the sender signature, decrypts the file, and saves it to disk.

## CLI commands

The CLI exposes the following user-facing commands:

- `register <username>`: create a user and generate a keypair
- `login <username>`: authenticate to the backend and save the session token
- `logout`: terminate the current session
- `whoami`: show the currently authenticated user
- `send <files> --to <recipients>`: send encrypted files to one or more recipients
- `inbox`: list pending messages available in the mailbox
- `receive <message-id>`: download, verify, and decrypt a message
- `encrypt <file>`: encrypt local files with AES-256
- `decrypt <file>`: decrypt files encrypted with the local AES key
- `sign <file>`: create a digital signature over a file
- `verify <file>`: verify a signature against a public key
- `extract`: helper utility for key extraction and file processing tasks

## Example workflow

```bash
./efss register alice
./efss login alice
./efss send confidential.pdf --to bob
./efss logout

./efss login bob
./efss inbox
./efss receive 1 --output recovered.pdf
```

## Notes

This project is intentionally designed as an educational security prototype rather than a production-grade SaaS platform. It demonstrates how to combine practical cryptographic mechanisms in a small end-to-end workflow while preserving clarity and readability for academic evaluation.

## Project attribution

This project was developed as part of the final exam for the course "Sicurezza dell'informazione M" at the University of Bologna (Unibo).

## License

This project is distributed under the MIT License. See [LICENSE](LICENSE) for details.
