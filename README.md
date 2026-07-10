# Secure Multiprocessor TCP Application Server

A secure TCP client-server application built using a C-based server and a Python client.

This project demonstrates secure network application development concepts such as custom TCP message framing, process-based concurrency, authentication, session management, abuse protection, and persistent audit logging.

## Project Overview

The system consists of:

- A TCP server implemented in C
- A Python client for communication and testing
- A custom LEN-based application protocol
- Fork-based multiprocessing for handling multiple clients
- Secure authentication with salted password hashing
- Token-based session management
- Abuse protection mechanisms
- Persistent audit logging

## Key Features

- C-based TCP server
- Python-based TCP client
- Custom `LEN:<n>` message framing protocol
- Handling of partial `recv()` data
- Handling of multiple messages received in one TCP buffer
- Payload overflow rejection for requests larger than 4096 bytes
- Concurrent client handling using `fork()`
- `SIGCHLD` and `waitpid()` handling to prevent zombie processes
- User registration and login
- Salted password hashing instead of plain-text password storage
- Session token generation after login
- Token-protected commands
- Session timeout after inactivity
- Brute-force login lockout
- Rate limiting per client
- Username validation
- Persistent audit logging with timestamp, client address, process ID, username, command, and result

## Technologies Used

- C
- Python
- Linux
- TCP Sockets
- fork()
- Makefile
- Secure Authentication
- Audit Logging

## Screenshots

### Project Files
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/01-project-files.png.png

### Server Running
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/02-server-running.png.png

### TCP Port Listening Proof
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/03-port-listening.png.png

### Register and Login Success
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/04-register-login.png.png

### Token-Protected Commands
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/05-token-protected-commands.png.png

### Brute-force Lockout
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/06-bruteforce-lockout.png.png

### Custom Protocol Test
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/07-protocol-test.png.png

### Fork-based Multiprocessing
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/08-fork-processes.png.png

### Audit Logging
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/09-audit-logging.png.png
### NO Zombie Processes
https://github.com/hashen16/secure-multiprocessor-tcp-server/blob/main/screenshots/Child-process-cleanup-No-zombie-processes.png.png
