#!/usr/bin/env python3
import sys, os, argparse, base64, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def write_bytes(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

def read_bytes(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def generate_key(out_path: str):
    key = AESGCM.generate_key(bit_length=256)  # 256-bit
    write_bytes(out_path, key)
    print(f"Chave AES-256 criada em: {out_path} (guarde com segurança)")

def encrypt(key_path: str, out_path: str):
    key = read_bytes(key_path)
    aes = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recomendado para GCM
    plaintext = sys.stdin.buffer.read()
    if not plaintext:
        print("Nada recebido via stdin. Ex.: echo 'mensagem' | python symmetric_aes.py encrypt --key aes.key --out msg.sim", file=sys.stderr)
        sys.exit(1)

    # Opcional: dados associados (AAD) podem ser autenticados sem serem cifrados
    aad = b"atividade-criptografia-aes-gcm"
    ciphertext = aes.encrypt(nonce, plaintext, aad)

    blob = {
        "nonce_b64": base64.b64encode(nonce).decode(),
        "aad_b64": base64.b64encode(aad).decode(),
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(blob, f, ensure_ascii=False, indent=2)
    print(f"Arquivo cifrado salvo em: {out_path}")

def decrypt(key_path: str, in_path: str):
    key = read_bytes(key_path)
    aes = AESGCM(key)
    with open(in_path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    nonce = base64.b64decode(blob["nonce_b64"])
    aad = base64.b64decode(blob["aad_b64"])
    ciphertext = base64.b64decode(blob["ciphertext_b64"])

    plaintext = aes.decrypt(nonce, ciphertext, aad)
    sys.stdout.buffer.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description="AES-GCM (simétrico) — cifrar/decifrar via stdin/stdout.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gk = sub.add_parser("generate-key", help="Gera nova chave AES-256")
    gk.add_argument("--out", required=True, help="Caminho do arquivo de chave (ex.: aes.key)")

    enc = sub.add_parser("encrypt", help="Cifra dados do stdin para JSON")
    enc.add_argument("--key", required=True, help="Arquivo de chave AES (ex.: aes.key)")
    enc.add_argument("--out", required=True, help="Arquivo de saída (ex.: msg.sim)")

    dec = sub.add_parser("decrypt", help="Decifra JSON para stdout")
    dec.add_argument("--key", required=True, help="Arquivo de chave AES (ex.: aes.key)")
    dec.add_argument("--in", dest="infile", required=True, help="Arquivo de entrada (ex.: msg.sim)")

    args = parser.parse_args()
    if args.cmd == "generate-key":
        generate_key(args.out)
    elif args.cmd == "encrypt":
        encrypt(args.key, args.out)
    elif args.cmd == "decrypt":
        decrypt(args.key, args.infile)

if __name__ == "__main__":
    main()
