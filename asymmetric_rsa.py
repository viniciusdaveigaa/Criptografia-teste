#!/usr/bin/env python3
import sys, argparse, base64, json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def write_text(path, txt: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt)

def read_bytes(path) -> bytes:
    with open(path, "rb") as f:
        return f.read()

def generate_keys(priv_path: str, pub_path: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f:
        f.write(priv_pem)
    with open(pub_path, "wb") as f:
        f.write(pub_pem)
    print(f"Chave privada: {priv_path}")
    print(f"Chave pública: {pub_path}")

def encrypt(pub_path: str, out_path: str):
    public_key = serialization.load_pem_public_key(read_bytes(pub_path))
    data = sys.stdin.buffer.read()
    if not data:
        print("Nada recebido via stdin. Ex.: echo 'mensagem' | python asymmetric_rsa.py encrypt --pub public.pem --out msg.asym", file=sys.stderr)
        sys.exit(1)

    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    blob = {
        "ciphertext_b64": base64.b64encode(ciphertext).decode()
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(blob, f, ensure_ascii=False, indent=2)
    print(f"Arquivo cifrado salvo em: {out_path}")

def decrypt(priv_path: str, in_path: str):
    private_key = serialization.load_pem_private_key(read_bytes(priv_path), password=None)
    with open(in_path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    ciphertext = base64.b64decode(blob["ciphertext_b64"])
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    sys.stdout.buffer.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description="RSA-OAEP (assimétrico) — cifrar/decifrar via stdin/stdout.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    gk = sub.add_parser("generate-keys", help="Gera par RSA (privada e pública)")
    gk.add_argument("--priv", required=True, help="Arquivo PEM da chave privada (ex.: private.pem)")
    gk.add_argument("--pub", required=True, help="Arquivo PEM da chave pública (ex.: public.pem)")

    enc = sub.add_parser("encrypt", help="Cifra dados do stdin com a PÚBLICA")
    enc.add_argument("--pub", required=True, help="Arquivo PEM da chave pública (ex.: public.pem)")
    enc.add_argument("--out", required=True, help="Arquivo de saída (ex.: msg.asym)")

    dec = sub.add_parser("decrypt", help="Decifra com a PRIVADA")
    dec.add_argument("--priv", required=True, help="Arquivo PEM da chave privada (ex.: private.pem)")
    dec.add_argument("--in", dest="infile", required=True, help="Arquivo de entrada (ex.: msg.asym)")

    args = parser.parse_args()
    if args.cmd == "generate-keys":
        generate_keys(args.priv, args.pub)
    elif args.cmd == "encrypt":
        encrypt(args.pub, args.out)
    elif args.cmd == "decrypt":
        decrypt(args.priv, args.infile)

if __name__ == "__main__":
    main()
