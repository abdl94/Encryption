import argparse
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
RSA_MODULE = None


def env_text(name, default):
    return os.environ.get(name, default)


def env_path(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def env_int(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    try:
        return int(value)
    except ValueError:
        return default


DEFAULT_PUBLIC_KEY_PATH = env_path("RSA_PUBLIC_KEY_PATH", SCRIPT_DIR / "public_key.txt")
DEFAULT_PRIVATE_KEY_PATH = env_path("RSA_PRIVATE_KEY_PATH", SCRIPT_DIR / "private_key.txt")
DEFAULT_SIGNATURE_PATH = env_path("RSA_SIGNATURE_PATH", SCRIPT_DIR / "signature")
DEFAULT_ENCRYPTED_PATH = env_path("RSA_ENCRYPTED_PATH", SCRIPT_DIR / "encrypted_message.bin")
DEFAULT_KEY_BITS = env_int("RSA_KEY_BITS", 2048)
HASH_METHOD = env_text("RSA_HASH_METHOD", "SHA-256")


def load_rsa_module():
    global RSA_MODULE
    if RSA_MODULE is not None:
        return RSA_MODULE

    original_sys_path = list(sys.path)
    try:
        sys.path = [
            path
            for path in sys.path
            if path not in {str(SCRIPT_DIR), str(REPO_ROOT)}
        ]
        import rsa as rsa_module
    except ModuleNotFoundError as exc:
        if exc.name == "rsa":
            raise RuntimeError(
                "Missing dependency 'rsa'. Install it with "
                "'python3 -m pip install -r requirements.txt'."
            ) from exc
        raise
    finally:
        sys.path = original_sys_path

    RSA_MODULE = rsa_module
    return RSA_MODULE


def generate_keys(
    public_key_path=DEFAULT_PUBLIC_KEY_PATH,
    private_key_path=DEFAULT_PRIVATE_KEY_PATH,
    bits=2048,
):
    rsa_module = load_rsa_module()
    public_key, private_key = rsa_module.newkeys(bits)
    public_key_path.write_bytes(public_key.save_pkcs1())
    private_key_path.write_bytes(private_key.save_pkcs1())
    return public_key_path, private_key_path


def load_public_key(path=DEFAULT_PUBLIC_KEY_PATH):
    rsa_module = load_rsa_module()
    return rsa_module.PublicKey.load_pkcs1(path.read_bytes())


def load_private_key(path=DEFAULT_PRIVATE_KEY_PATH):
    rsa_module = load_rsa_module()
    return rsa_module.PrivateKey.load_pkcs1(path.read_bytes())


def sign_message(
    message_to_sign,
    private_key_path=DEFAULT_PRIVATE_KEY_PATH,
    signature_path=DEFAULT_SIGNATURE_PATH,
):
    rsa_module = load_rsa_module()
    signature = rsa_module.sign(
        message_to_sign.encode("utf-8"),
        load_private_key(private_key_path),
        HASH_METHOD,
    )
    signature_path.write_bytes(signature)
    return signature_path


def verify_message(
    message_to_sign,
    public_key_path=DEFAULT_PUBLIC_KEY_PATH,
    signature_path=DEFAULT_SIGNATURE_PATH,
):
    rsa_module = load_rsa_module()
    signature = signature_path.read_bytes()
    return rsa_module.verify(
        message_to_sign.encode("utf-8"),
        signature,
        load_public_key(public_key_path),
    )


def encrypt_message(
    message,
    public_key_path=DEFAULT_PUBLIC_KEY_PATH,
    output_path=DEFAULT_ENCRYPTED_PATH,
):
    rsa_module = load_rsa_module()
    ciphertext = rsa_module.encrypt(
        message.encode("utf-8"), load_public_key(public_key_path)
    )
    output_path.write_bytes(ciphertext)
    return output_path


def decrypt_message(
    encrypted_path=DEFAULT_ENCRYPTED_PATH,
    private_key_path=DEFAULT_PRIVATE_KEY_PATH,
):
    rsa_module = load_rsa_module()
    plaintext = rsa_module.decrypt(
        encrypted_path.read_bytes(), load_private_key(private_key_path)
    )
    return plaintext


def build_parser():
    parser = argparse.ArgumentParser(description="RSA CLI.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_keys_parser = subparsers.add_parser(
        "generate-keys", help="Generate a new RSA key pair."
    )
    generate_keys_parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY_PATH,
        help=f"Public key output path. Default: {DEFAULT_PUBLIC_KEY_PATH.name}",
    )
    generate_keys_parser.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY_PATH,
        help=f"Private key output path. Default: {DEFAULT_PRIVATE_KEY_PATH.name}",
    )
    generate_keys_parser.add_argument(
        "--bits",
        type=int,
        default=DEFAULT_KEY_BITS,
        help=f"RSA key size in bits. Default: {DEFAULT_KEY_BITS}",
    )

    sign_parser = subparsers.add_parser(
        "sign", help="Sign a message with the private key."
    )
    sign_parser.add_argument("message", help="Message to sign.")
    sign_parser.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY_PATH,
        help=f"Private key path. Default: {DEFAULT_PRIVATE_KEY_PATH.name}",
    )
    sign_parser.add_argument(
        "--signature",
        type=Path,
        default=DEFAULT_SIGNATURE_PATH,
        help=f"Signature output path. Default: {DEFAULT_SIGNATURE_PATH.name}",
    )

    verify_parser = subparsers.add_parser("verify", help="Verify a signed message.")
    verify_parser.add_argument("message", help="Message to verify.")
    verify_parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY_PATH,
        help=f"Public key path. Default: {DEFAULT_PUBLIC_KEY_PATH.name}",
    )
    verify_parser.add_argument(
        "--signature",
        type=Path,
        default=DEFAULT_SIGNATURE_PATH,
        help=f"Signature path. Default: {DEFAULT_SIGNATURE_PATH.name}",
    )

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a short message with the public key."
    )
    encrypt_parser.add_argument("message", help="Message to encrypt.")
    encrypt_parser.add_argument(
        "--public-key",
        type=Path,
        default=DEFAULT_PUBLIC_KEY_PATH,
        help=f"Public key path. Default: {DEFAULT_PUBLIC_KEY_PATH.name}",
    )
    encrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_ENCRYPTED_PATH,
        help=f"Ciphertext output path. Default: {DEFAULT_ENCRYPTED_PATH.name}",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt a message with the private key."
    )
    decrypt_parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_ENCRYPTED_PATH,
        help=f"Ciphertext input path. Default: {DEFAULT_ENCRYPTED_PATH.name}",
    )
    decrypt_parser.add_argument(
        "--private-key",
        type=Path,
        default=DEFAULT_PRIVATE_KEY_PATH,
        help=f"Private key path. Default: {DEFAULT_PRIVATE_KEY_PATH.name}",
    )
    decrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional file to store the decrypted plaintext.",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        rsa_module = load_rsa_module()
    except RuntimeError as exc:
        parser.exit(status=1, message=f"{exc}\n")

    try:
        if args.command == "generate-keys":
            public_key_path, private_key_path = generate_keys(
                public_key_path=args.public_key,
                private_key_path=args.private_key,
                bits=args.bits,
            )
            print(f"Generated RSA key pair: {public_key_path}, {private_key_path}")
            return 0

        if args.command == "sign":
            signature_path = sign_message(
                args.message,
                private_key_path=args.private_key,
                signature_path=args.signature,
            )
            print(f"Saved signature to {signature_path}.")
            return 0

        if args.command == "verify":
            hash_method = verify_message(
                args.message,
                public_key_path=args.public_key,
                signature_path=args.signature,
            )
            print(f"Signature verified with {hash_method}.")
            return 0

        if args.command == "encrypt":
            ciphertext_path = encrypt_message(
                args.message,
                public_key_path=args.public_key,
                output_path=args.output,
            )
            print(f"Saved encrypted message to {ciphertext_path}.")
            return 0

        plaintext = decrypt_message(
            encrypted_path=args.input,
            private_key_path=args.private_key,
        )
    except FileNotFoundError as exc:
        parser.error(f"missing required file: {exc.filename}")
    except rsa_module.VerificationError:
        print("Signature verification failed.")
        return 1
    except rsa_module.DecryptionError:
        print("Unable to decrypt message with the provided private key.")
        return 1

    if args.output:
        args.output.write_bytes(plaintext)
        print(f"Saved decrypted message to {args.output}.")

    try:
        print(f"Decrypted message: {plaintext.decode('utf-8')}")
    except UnicodeDecodeError:
        print(f"Decrypted {len(plaintext)} bytes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
