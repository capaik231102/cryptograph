import streamlit as st
import base64
import hashlib
from Crypto.Cipher import DES, AES, ARC4
from Crypto.Util.Padding import pad, unpad
import os

# Fungsi untuk mengonversi kunci ke SHA-256
def get_key(key, length):
    return hashlib.sha256(key.encode()).digest()[:length]

# Fungsi Simple XOR
def simple_xor(data, key):
    key = key.encode()
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

# Fungsi RC4
def rc4_encrypt_decrypt(key, data):
    cipher = ARC4.new(get_key(key, 16))
    return cipher.encrypt(data)

# Fungsi DES
def des_encrypt(key, data, mode):
    key = get_key(key, 8)
    iv = os.urandom(DES.block_size)
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(pad(data, DES.block_size))
    elif mode == 'CBC':
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, DES.block_size))

def des_decrypt(key, data, mode):
    key = get_key(key, 8)
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        return unpad(cipher.decrypt(data), DES.block_size)
    elif mode == 'CBC':
        iv, encrypted_data = data[:DES.block_size], data[DES.block_size:]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), DES.block_size)

# Fungsi AES
def aes_encrypt(key, data, mode):
    key = get_key(key, 16)
    iv = os.urandom(AES.block_size)
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(data, AES.block_size))
    elif mode == 'CBC':
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(key, data, mode):
    key = get_key(key, 16)
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), AES.block_size)
    elif mode == 'CBC':
        iv, encrypted_data = data[:AES.block_size], data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(encrypted_data), AES.block_size)

# Streamlit UI
st.set_page_config(page_title="Aplikasi Enkripsi & Dekripsi", page_icon="🔒", layout="wide")

st.markdown(
    """
    <style>
    html, body, [class*="stApp"] {
        background-image: url('https://plus.unsplash.com/premium_photo-1661964184053-91aa3dc5f508?q=100&w=3840&auto=format&fit=crop');
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
        background-repeat: no-repeat;
    }
    .title, .description, label {
        font-weight: bold !important;
        color: black;
    }
    label {
        font-size: 12px !important;
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.markdown("""
    <h1 class='title' style='text-align:center;'>🔐 Aplikasi Enkripsi dan Dekripsi</h1>
    <p class='description' style='text-align:center;'>
        Gunakan aplikasi ini untuk mengenkripsi dan mendekripsi teks atau file dengan berbagai metode.
    </p>
""", unsafe_allow_html=True)

option = st.radio("**Pilih Menu**", ["Enkripsi", "Dekripsi"], horizontal=True)

if option == "Enkripsi":
    method = st.selectbox("**Pilih Metode**", ["Simple XOR", "RC4", "DES", "AES"])
    key = st.text_input("🔑 **Masukkan Kunci**", type="password")
    message = st.text_area("📝 **Masukkan Pesan (Opsional)**")
    uploaded_file = st.file_uploader("📂 **Upload File untuk Enkripsi**")
    
    mode = None
    if method in ["DES", "AES"]:
        mode = st.selectbox("⚙️ **Pilih Mode**", ["ECB", "CBC"])
    
    if st.button("🔒 **Enkripsi**"):
        if not key:
            st.error("❌ Harap masukkan kunci!")
        else:
            if message:
                data = message.encode()
                filename = None
            elif uploaded_file:
                data = uploaded_file.read()
                filename = uploaded_file.name
            else:
                st.error("❌ Harap masukkan pesan atau unggah file!")
                st.stop()

            if method == "Simple XOR":
                encrypted = simple_xor(data, key)
            elif method == "RC4":
                encrypted = rc4_encrypt_decrypt(key, data)
            elif method == "DES":
                encrypted = des_encrypt(key, data, mode)
            elif method == "AES":
                encrypted = aes_encrypt(key, data, mode)
            
            st.success("✅ Data Berhasil Dienkripsi!")
            if filename:
                st.download_button("📥 **Unduh File Terenkripsi**", encrypted, file_name=f"{filename}.enc")
            else:
                encrypted_b64 = base64.b64encode(encrypted).decode()
                st.text_area("🔐 **Hasil Enkripsi**", encrypted_b64, height=100)

elif option == "Dekripsi":
    method = st.selectbox("**Pilih Metode**", ["Simple XOR", "RC4", "DES", "AES"])
    key = st.text_input("🔑 **Masukkan Kunci**", type="password")
    encrypted_message = st.text_area("🔏 **Masukkan Ciphertext (Base64)**")
    uploaded_file = st.file_uploader("📂 **Upload File untuk Dekripsi**")
    
    mode = None
    if method in ["DES", "AES"]:
        mode = st.selectbox("⚙️ **Pilih Mode**", ["ECB", "CBC"])
    
    if st.button("🔓 **Dekripsi**"):
        if not key:
            st.error("❌ Harap masukkan kunci!")
        else:
            if encrypted_message:
                encrypted_data = base64.b64decode(encrypted_message)
                filename = None
            elif uploaded_file:
                encrypted_data = uploaded_file.read()
                filename = uploaded_file.name.replace(".enc", "")
            else:
                st.error("❌ Harap masukkan cipherteks atau unggah file!")
                st.stop()

            if method == "Simple XOR":
                decrypted = simple_xor(encrypted_data, key)
            elif method == "RC4":
                decrypted = rc4_encrypt_decrypt(key, encrypted_data)
            elif method == "DES":
                decrypted = des_decrypt(key, encrypted_data, mode)
            elif method == "AES":
                decrypted = aes_decrypt(key, encrypted_data, mode)
            
            st.success("✅ Data Berhasil Didekripsi!")
            st.text_area("🔓 **Hasil Dekripsi**", decrypted.decode(errors='ignore'), height=100)
