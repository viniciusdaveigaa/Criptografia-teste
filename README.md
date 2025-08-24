# Atividade Complementar - Criptografia

Este projeto mostra como **cifrar e decifrar textos** com dois tipos de chave:

- **AES (simétrica)**
- **RSA (assimétrica)**

## Instalação

```bash
pip install -r requirements.txt
```

## AES (simétrica)

Gerar chave:

```bash
python symmetric_aes.py generate-key --out aes.key
```

Cifrar:

```bash
echo "mensagem" | python symmetric_aes.py encrypt --key aes.key --out msg.sim
```

Decifrar:

```bash
python symmetric_aes.py decrypt --key aes.key --in msg.sim
```

## RSA (assimétrica)

Gerar par de chaves:

```bash
python asymmetric_rsa.py generate-keys --priv private.pem --pub public.pem
```

Cifrar:

```bash
echo "mensagem" | python asymmetric_rsa.py encrypt --pub public.pem --out msg.asym
```

Decifrar:

```bash
python asymmetric_rsa.py decrypt --priv private.pem --in msg.asym
```
