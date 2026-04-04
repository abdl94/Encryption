import argparse
import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent


def env_text(name, default):
    return os.environ.get(name, default)


def env_path(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


DEFAULT_KEY_TEXT = env_text("AES_KEY", "1234567891234567")
DEFAULT_INPUT_PATH = env_path("AES_INPUT_PATH", SCRIPT_DIR / "file_to_encrypt")
DEFAULT_OUTPUT_PATH = env_path("AES_ENCRYPTED_PATH", SCRIPT_DIR / "encrypted.aes")


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


def encrypt_file(input_path, output_path, key):
    aes_module = load_aes_module()
    plaintext = input_path.read_bytes()
    cipher = aes_module.new(key, aes_module.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    output_path.write_bytes(tag + cipher.nonce + ciphertext)
    return len(plaintext)


def build_parser():
    parser = argparse.ArgumentParser(description="Encrypt a file with AES-OCB.")
    parser.add_argument(
        "input_path",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"Path to the plaintext file. Default: {DEFAULT_INPUT_PATH.name}",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Path for the encrypted output. Default: {DEFAULT_OUTPUT_PATH.name}",
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
        plaintext_size = encrypt_file(args.input_path, args.output, args.key)
    except FileNotFoundError:
        parser.error(f"input file not found: {args.input_path}")
    except RuntimeError as exc:
        parser.exit(status=1, message=f"{exc}\n")

    print(
        f"Encrypted {plaintext_size} bytes from {args.input_path} to {args.output}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
