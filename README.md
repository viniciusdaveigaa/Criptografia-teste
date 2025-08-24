# Atividade Complementar — Criptografia (Chave Simétrica e Assimétrica)

Este projeto demonstra **cifragem e decifragem** de textos com:

1. **Chave simétrica (AES-GCM)** — `symmetric_aes.py`
2. **Chave assimétrica (RSA-OAEP)** — `asymmetric_rsa.py`

Ambas as implementações usam a biblioteca [`cryptography`](https://pypi.org/project/cryptography/).

---

## ✅ Requisitos
- Python 3.10+
- pip
- Sistema operacional com OpenSSL instalado (normalmente já vem por padrão).

Instale as dependências:
```bash
pip install -r requirements.txt
```

---

## 1) AES-GCM (Simétrica)

- **Gera** uma chave aleatória (ou usa uma informada por arquivo).
- **Cifra** um texto usando `AES-GCM` (autenticado).
- **Decifra** um texto com a mesma chave.

### Exemplos
Gerar nova chave e cifrar:
```bash
python symmetric_aes.py generate-key --out aes.key
echo "mensagem secreta" | python symmetric_aes.py encrypt --key aes.key --out msg.sim
```

Decifrar:
```bash
python symmetric_aes.py decrypt --key aes.key --in msg.sim
```

A saída padrão exibirá o texto em claro.

---

## 2) RSA-OAEP (Assimétrica)

- **Gera** um par de chaves (privada + pública) no formato PEM.
- **Cifra** com a **chave pública**.
- **Decifra** com a **chave privada**.

> Observação: RSA tem limite de tamanho de mensagem. Para fins didáticos, aqui ciframos mensagens curtas diretamente. Em produção, recomenda-se **RSA híbrido** (RSA para cifrar a chave simétrica + AES para os dados).

### Exemplos
Gerar par de chaves:
```bash
python asymmetric_rsa.py generate-keys --priv private.pem --pub public.pem
```

Cifrar com a pública (mensagem curta):
```bash
echo "texto top secreto" | python asymmetric_rsa.py encrypt --pub public.pem --out msg.asym
```

Decifrar com a privada:
```bash
python asymmetric_rsa.py decrypt --priv private.pem --in msg.asym
```

---

## Estrutura
```
.
├── asymmetric_rsa.py
├── symmetric_aes.py
├── requirements.txt
└── README.md
```

---

## Como postar no GitHub

1. Crie um repositório **público** no GitHub (ex.: `criptografia-atividade`).
2. No seu computador:
```bash
git clone https://github.com/<seu-usuario>/criptografia-atividade.git
cd criptografia-atividade
# copie estes arquivos para dentro da pasta clonada (ou baixe o ZIP e extraia aqui)
git add .
git commit -m "Atividade complementar - criptografia (AES-GCM e RSA-OAEP)"
git push origin main
```
3. Entregue o **link do repositório** no Classroom.

---

## Segurança (nota rápida)
- **AES-GCM** provê confidencialidade e integridade (tag de autenticação).
- **RSA-OAEP** é mais seguro do que RSA “puro”. Aqui usamos `MGF1` com `SHA256`.

> Código feito **para fins acadêmicos**. Para produção, revise práticas de rotação de chaves, KDF, armazenamento seguro, tamanho de chaves e manejo de exceções/erros.
