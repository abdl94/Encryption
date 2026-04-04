import argparse
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TAG_SIZE = 16
NONCE_SIZE = 15


def env_text(name, default):
    return os.environ.get(name, default)


def env_path(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


DEFAULT_KEY_TEXT = env_text("AES_KEY", "1234567891234567")
DEFAULT_INPUT_PATH = env_path("AES_ENCRYPTED_PATH", SCRIPT_DIR / "encrypted.aes")
DEFAULT_OUTPUT_PATH = env_path("AES_DECRYPTED_PATH", SCRIPT_DIR / "decrypted_file")


def parse_key(key_text):
    key = key_text.encode("utf-8")
    if len(key) not in (16, 24, 32):
        raise argparse.ArgumentTypeError(
            "AES key must be 16, 24, or 32 bytes after UTF-8 encoding."
        )
    return key


def load_aes_module():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as exc:
        if exc.name == "Crypto":
            raise RuntimeError(
                "Missing dependency 'pycryptodome'. Install it with "
                "'python3 -m pip install -r requirements.txt'."
            ) from exc
        raise
    return AES


def decrypt_file(input_path, output_path, key):
    aes_module = load_aes_module()
    encrypted_payload = input_path.read_bytes()
    if len(encrypted_payload) < TAG_SIZE + NONCE_SIZE:
        raise ValueError("Encrypted file is too short to contain tag and nonce.")

    tag = encrypted_payload[:TAG_SIZE]
    nonce = encrypted_payload[TAG_SIZE : TAG_SIZE + NONCE_SIZE]
    ciphertext = encrypted_payload[TAG_SIZE + NONCE_SIZE :]

    cipher = aes_module.new(key, aes_module.MODE_OCB, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    output_path.write_bytes(plaintext)
    return plaintext


def build_parser():
    parser = argparse.ArgumentParser(description="Decrypt a file encrypted with AES-OCB.")
    parser.add_argument(
        "input_path",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Path to the encrypted file. Default: {DEFAULT_INPUT_PATH.name}",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Path for the decrypted output. Default: {DEFAULT_OUTPUT_PATH.name}",
    )
    parser.add_argument(
        "-k",
        "--key",
        default=DEFAULT_KEY_TEXT,
        type=parse_key,
        help="AES key text. Must encode to 16, 24, or 32 bytes.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        plaintext = decrypt_file(args.input_path, args.output, args.key)
    except FileNotFoundError:
        parser.error(f"input file not found: {args.input_path}")
    except RuntimeError as exc:
        parser.exit(status=1, message=f"{exc}\n")
    except ValueError as exc:
        print(f"Unable to decrypt {args.input_path}: {exc}", file=sys.stderr)
        return 1

    try:
        preview = plaintext.decode("utf-8")
    except UnicodeDecodeError:
        print(f"Decrypted {len(plaintext)} bytes to {args.output}.")
    else:
        print(f"Decrypted message: {preview}")
        print(f"Saved plaintext to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
