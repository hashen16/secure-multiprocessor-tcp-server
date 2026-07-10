#!/usr/bin/env python3

import argparse
import os
import re
import socket
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 50456


def build_frame(payload: str) -> bytes:
    data = payload.encode("utf-8")
    header = f"LEN:{len(data)}\n".encode("ascii")
    return header + data


def recv_response(sock: socket.socket) -> str:
    data = b""

    while not data.endswith(b"\n"):
        part = sock.recv(4096)

        if not part:
            break

        data += part

    return data.decode("utf-8", errors="replace").strip()


def send_command(sock: socket.socket, command: str) -> str:
    sock.sendall(build_frame(command))
    return recv_response(sock)


def interactive(host: str, port: int) -> None:
    with socket.create_connection((host, port)) as sock:
        print(recv_response(sock))

        print("Type commands. Examples:")
        print("  REGISTER amal MyPass123")
        print("  LOGIN amal MyPass123")
        print("  WHOAMI <token>")
        print("  PING <token>")
        print("  LOGOUT <token>")
        print("Type exit to close.")

        while True:
            try:
                command = input("IE2102> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not command:
                continue

            if command.lower() in {"exit", "quit"}:
                break

            response = send_command(sock, command)

            print(response)


def auto_mode(host: str, port: int, username: str, password: str, hold: int) -> None:
    with socket.create_connection((host, port)) as sock:
        print(recv_response(sock))

        commands = [
            f"REGISTER {username} {password}",
            f"LOGIN {username} {password}",
        ]

        token = None

        for cmd in commands:
            response = send_command(sock, cmd)

            print(f"> {cmd}")
            print(response)

            match = re.search(r"TOKEN:(\S+)", response)

            if match:
                token = match.group(1)

        if token:
            protected_commands = [
                f"WHOAMI {token}",
                f"PING {token}",
            ]

            for cmd in protected_commands:
                response = send_command(sock, cmd)

                print(f"> {cmd}")
                print(response)

            if hold > 0:
                print(f"Holding connection for {hold} seconds. PID={os.getpid()}")
                time.sleep(hold)

            response = send_command(sock, f"LOGOUT {token}")

            print(f"> LOGOUT {token}")
            print(response)


def test_protocol(host: str, port: int) -> None:
    with socket.create_connection((host, port)) as sock:
        print(recv_response(sock))

        print("\n[1] Partial recv test")

        payload = "HELP"
        frame = build_frame(payload)

        sock.sendall(frame[:3])
        time.sleep(0.5)
        sock.sendall(frame[3:])

        print(recv_response(sock))

        print("\n[2] Multiple messages in one buffer test")

        combo = build_frame("HELP") + build_frame("HELP")

        sock.sendall(combo)

        print(recv_response(sock))
        print(recv_response(sock))

    print("\n[3] Oversized payload test")

    with socket.create_connection((host, port)) as sock:
        print(recv_response(sock))

        big_payload = "A" * 4097

        sock.sendall(f"LEN:{len(big_payload)}\n".encode("ascii") + big_payload.encode("ascii"))

        print(recv_response(sock))


def main() -> None:
    parser = argparse.ArgumentParser(description="IE2102 framed TCP client for IT24123456")

    parser.add_argument("host", nargs="?", default=DEFAULT_HOST)
    parser.add_argument("port", nargs="?", type=int, default=DEFAULT_PORT)

    parser.add_argument(
        "--auto",
        nargs=2,
        metavar=("USER", "PASS"),
        help="Run automatic register/login/protected-command test",
    )

    parser.add_argument(
        "--hold",
        type=int,
        default=0,
        help="Hold connection open for N seconds in auto mode",
    )

    parser.add_argument(
        "--test-protocol",
        action="store_true",
        help="Test partial recv, multiple messages, and oversized payload",
    )

    args = parser.parse_args()

    if args.test_protocol:
        test_protocol(args.host, args.port)
    elif args.auto:
        username, password = args.auto
        auto_mode(args.host, args.port, username, password, args.hold)
    else:
        interactive(args.host, args.port)


if __name__ == "__main__":
    main()
