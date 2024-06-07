import streamlit as st
import pandas as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Variables globales para almacenar las claves públicas y privadas
public_keys = {}
private_keys = {}

# Leer las claves públicas y privadas desde un archivo Excel
def load_keys_from_excel(file):
    global public_keys, private_keys
    try:
        df = pd.read_excel(file)
        for index, row in df.iterrows():
            # Convertir los valores numéricos de las claves a objetos de clave RSA
            n = int(row[1])  # Modulus
            e = int(row[2])  # Public exponent
            d = int(row[3])  # Private exponent
            p = int(row[4])  # Prime p
            q = int(row[5])  # Prime q
            dp = int(row[6]) # d mod (p-1)
            dq = int(row[7]) # d mod (q-1)
            qi = int(row[8]) # q^-1 mod p
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            private_key = rsa.RSAPrivateNumbers(
                p=p, q=q, d=d, dmp1=dp, dmq1=dq, iqmp=qi,
                public_numbers=rsa.RSAPublicNumbers(e, n)
            ).private_key()
            # Almacenar las claves en los diccionarios
            public_keys[row[0]] = public_key
            private_keys[row[0]] = private_key

    except Exception as e:
        st.error(f"Error al leer el archivo Excel: {e}")

# Generar un hash del documento o cadena de caracteres
def create_hash(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

# Firmar el hash utilizando la clave privada
def sign_data(data: bytes, signer: str) -> bytes:
    global private_keys
    private_key = private_keys.get(signer)
    if private_key is None:
        st.error(f"No se encontró la clave privada para el firmante: {signer}")
        return None
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

# Verificar la firma utilizando la clave pública
def verify_signature(data: bytes, signature: bytes, signer: str) -> bool:
    global public_keys
    public_key = public_keys.get(signer)
    if public_key is None:
        st.error(f"No se encontró la clave pública para el firmante: {signer}")
        return False
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        st.error(f"Error al verificar la firma: {e}")
        return False

# Interfaz de usuario con Streamlit
st.title("Generador y Verificador de Firmas Digitales")

# Cargar las claves desde un archivo Excel
st.header("Cargar Claves desde Excel")
uploaded_excel = st.file_uploader("Sube el archivo Excel con las claves", type=["xlsx"])
if uploaded_excel:
    load_keys_from_excel(uploaded_excel)
    st.success("Claves cargadas con éxito")

# Generar firma digital
st.header("Generar Firma Digital")
signer_info = st.text_input("Nombre del firmante")
uploaded_document = st.file_uploader("Sube el documento a firmar", type=["txt", "pdf"], key="sign_doc")
if st.button("Generar Firma"):
    if signer_info in private_keys and uploaded_document:
        document = uploaded_docume

