#!/usr/bin/env python3
"""Check the TLS ClientHello random from PalmTLS RNG Test on cp-uarm."""

import hmac
import socket


def digest(key, message):
    return hmac.digest(key, message, "sha256")


def expected_random():
    key = bytes(32)
    value = bytes([1]) * 32
    test_seed = bytes(range(48))
    for separator in (b"\0", b"\1"):
        key = digest(key, value + separator + test_seed)
        value = digest(key, value)

    # With the pinned build, the two identities and the TLS key share
    # consume four single blocks and one two-block request.
    for blocks in (1, 1, 1, 1, 2):
        for _ in range(blocks):
            value = digest(key, value)
        key = digest(key, value + b"\0")
        value = digest(key, value)
    return digest(key, value)


def main():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 19444))
        listener.listen(1)
        listener.settimeout(60)
        print("Listening for the emulator ClientHello", flush=True)
        connection, _ = listener.accept()
        with connection, connection.makefile("rb") as stream:
            connection.settimeout(10)
            header = stream.read(5)
            if len(header) != 5 or header[0] != 22:
                raise ValueError("Expected a TLS handshake record")
            record = stream.read(int.from_bytes(header[3:5], "big"))
            if len(record) < 38 or record[0] != 1:
                raise ValueError("Expected the beginning of TLS ClientHello")
            if not hmac.compare_digest(record[6:38], expected_random()):
                raise ValueError("ClientHello random differs from the HMAC-DRBG vector")
    print("PASS: TLS ClientHello uses the seeded HMAC-DRBG")


if __name__ == "__main__":
    main()
