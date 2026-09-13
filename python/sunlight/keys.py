"""Key custody (spec §7 KeyApi, §8 LocalKeyFile).

Local key files are encrypted PKCS#8 PEM inside a LocalKeyFile JSON wrapper.
Files require owner-only permissions (0600); passphrases come from an
interactive terminal or SUNLIGHT_KEY_PASSPHRASE_FD — never argv.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, load_pem_private_key,
)

from .ed25519 import private_key_from_seed, public_from_seed
from .errors import SunlightError
from .fsutil import read_file_bytes, write_file_exclusive
from .ids import new_id
from .jcs import jcs
from .objects import Signer, seed_signer
from .schema import parse_local_key_file, parse_public_key
from .strictjson import parse_strict_json

_PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")


def der_to_seed(der: bytes) -> bytes:
    if len(der) != 48 or der[:16] != _PKCS8_ED25519_PREFIX:
        raise SunlightError("KEY_ERROR")
    return der[16:]


def read_passphrase() -> str:
    """SUNLIGHT_KEY_PASSPHRASE_FD supplies the passphrase on a file
    descriptor; otherwise an interactive terminal prompt is required."""
    fd_str = os.environ.get("SUNLIGHT_KEY_PASSPHRASE_FD")
    if fd_str:
        fd = int(fd_str)
        if fd < 0:
            raise SunlightError("USAGE")
        chunks = []
        while True:
            b = os.read(fd, 4096)
            if not b:
                break
            chunks.append(b)
            if b"\n" in b:
                break
        line = b"".join(chunks).decode("utf-8").split("\n")[0]
        return line.rstrip("\r")
    if os.isatty(0):
        import getpass

        return getpass.getpass("key passphrase: ")
    raise SunlightError(
        "KEY_ERROR", cause=ValueError("no passphrase source (set SUNLIGHT_KEY_PASSPHRASE_FD)")
    )


def generate_key(passphrase: str, entropy: bytes | None = None):
    """Entropy stream: first 32 bytes are the seed; further bytes drive the
    nanoid sampler so conformance runs are fully deterministic."""
    stream = entropy
    offset = [0]

    def take(n: int) -> bytes:
        if stream is None:
            return os.urandom(n)
        out = bytearray(n)
        for i in range(n):
            if offset[0] < len(stream):
                out[i] = stream[offset[0]]
                offset[0] += 1
            else:
                out[i] = os.urandom(1)[0]
        return bytes(out)

    seed = take(32)
    pub = public_from_seed(seed)
    key_id = new_id("slk", rand=lambda n: take(n))
    key = {"id": key_id, "public_hex": pub.hex()}
    pem = (
        private_key_from_seed(seed)
        .private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        .decode("ascii")
    )
    return {
        "key": key,
        "file": {"v": "sunlight.keyfile/1", "key": key, "encrypted_pkcs8_pem": pem},
        "seed": seed,
    }


def load_key_file(path: str, passphrase: str | None = None) -> Signer:
    """Load + decrypt a LocalKeyFile and verify the derived public key."""
    st = os.lstat(path)
    if not os.path.isfile(path):
        raise SunlightError("KEY_ERROR")
    if st.st_mode & 0o077:
        raise SunlightError("KEY_PERMISSIONS")
    try:
        parsed = parse_local_key_file(parse_strict_json(read_file_bytes(path)))
    except Exception as e:
        raise SunlightError("KEY_ERROR", cause=e) from e
    pw = passphrase if passphrase is not None else read_passphrase()
    try:
        priv = load_pem_private_key(
            parsed["encrypted_pkcs8_pem"].encode("ascii"),
            password=pw.encode("utf-8"),
        )
        der = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, serialization.NoEncryption())
        seed = der_to_seed(der)
    except Exception as e:
        raise SunlightError("KEY_ERROR", cause=e) from e
    if public_from_seed(seed).hex() != parsed["key"]["public_hex"]:
        raise SunlightError("KEY_ERROR")
    return seed_signer(parsed["key"], seed)


def write_key_file(path: str, file: dict) -> None:
    write_file_exclusive(path, jcs(file), 0o600)


def write_public_key_file(path: str, key: dict) -> None:
    write_file_exclusive(path, jcs(parse_public_key(key)), 0o600)


def key_file_from_seed(key_id: str, seed: bytes, passphrase: str) -> dict:
    key = {"id": key_id, "public_hex": public_from_seed(seed).hex()}
    pem = (
        private_key_from_seed(seed)
        .private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        .decode("ascii")
    )
    return {"v": "sunlight.keyfile/1", "key": key, "encrypted_pkcs8_pem": pem}
