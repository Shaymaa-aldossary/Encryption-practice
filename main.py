from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)


public_key = private_key.public_key()

with open("keys/private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"pass12345")
        )
    )

print("[+] تم حفظ private_key.pem")

with open("keys/public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("[+] تم حفظ public_key.pem")

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# توليد مفتاح AES (256-bit) و IV (128-bit)
aes_key = os.urandom(32)  # 32 بايت = 256 بت
iv = os.urandom(16)       # 16 بايت = 128 بت

# حفظ IV في ملف
with open("encrypted/iv.bin", "wb") as f:
    f.write(iv)

print("[+] تم توليد iv.bin")

# تحميل المفتاح العام لتشفير مفتاح AES
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

with open("keys/public_key.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# تشفير مفتاح AES باستخدام RSA
encrypted_aes_key = public_key.encrypt(
    aes_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# حفظ مفتاح AES المشفّر في ملف
with open("encrypted/aes_key.enc", "wb") as f:
    f.write(encrypted_aes_key)

print("[+] تم حفظ aes_key.enc بعد تشفيره باستخدام RSA")

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_file(input_path, output_path, key, iv):
    # قراءة البيانات
    with open(input_path, "rb") as f:
        data = f.read()

    # إضافة Padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # إعداد التشفير
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # تشفير البيانات
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # حفظ الملف المشفّر
    with open(output_path, "wb") as f:
        f.write(encrypted_data)

    print(f"[+] تم تشفير {input_path} → {output_path}")

# تشفير الملفات المطلوبة
encrypt_file("test_data/fake_data.json", "encrypted/fake_data.enc", aes_key, iv)
encrypt_file("test_data/fake_message.txt", "encrypted/fake_message.enc", aes_key, iv)

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, padding as sym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa

# فك تشفير AES
with open("keys/private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b"pass12345"
    )

with open("encrypted/aes_key.enc", "rb") as f:
    encrypted_key = f.read()

decrypted_key = private_key.decrypt(
    encrypted_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("تم فك تشفير مفتاح AES")

# قراءة IV من الملف
with open("encrypted/iv.bin", "rb") as f:
    iv = f.read()

# دالة لفك تشفير الملفات
def decrypt_file(input_path, output_path, key, iv):
    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # إزالة padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    with open(output_path, "wb") as f:
        f.write(data)

    print(f"[+] تم فك تشفير {input_path} → {output_path}")

# فك تشفير الملفات واسترجاعها
decrypt_file("encrypted/fake_data.enc", "decrypted/fake_data.json", decrypted_key, iv)
decrypt_file("encrypted/fake_message.enc", "decrypted/fake_message.txt", decrypted_key, iv)