from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import hashlib
import os

# ------------------- 密钥和加密工具函数 -------------------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def generate_aes_key():
    return Fernet.generate_key()

def encrypt_data(key, data):
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(key, encrypted_data):
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

# ------------------- 密码哈希和验证 -------------------
def hash_password_with_salt(password, salt):
    hasher = hashlib.sha256()
    hasher.update(salt + password.encode())
    return hasher.hexdigest(), salt

def verify_password(stored_hash, salt, input_password):
    new_hash, _ = hash_password_with_salt(input_password, salt)
    return new_hash == stored_hash

# ------------------- 服务端注册和存储 -------------------
def register():
    private_key_pem, public_key_pem = generate_rsa_keypair()
    with open("private_key.pem", "wb") as f:
        f.write(private_key_pem)
    return public_key_pem

def server_store_password(password):
    salt = os.urandom(16)
    hashed_password, _ = hash_password_with_salt(password, salt)
    aes_key = generate_aes_key()
    encrypted_hash = encrypt_data(aes_key, hashed_password)
    # 实际应存储到数据库，此处返回示例
    return salt, encrypted_hash, aes_key

# ------------------- 客户端加密 -------------------
def client_encrypt_password(public_key_pem: bytes, password: str) -> bytes:
    public_key = serialization.load_pem_public_key(public_key_pem)
    encrypted_password = public_key.encrypt(
        password.encode("utf-8"),
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_password

# ------------------- 服务端解密和验证 -------------------
def server_decrypt_password(private_key_pem, encrypted_password):
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    password_bytes = private_key.decrypt(
        encrypted_password,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return password_bytes.decode("utf-8")

def login(private_key_pem, encrypted_password, input_password):
    # 解密客户端密码
    decrypted_password = server_decrypt_password(private_key_pem, encrypted_password)
    
    # 模拟从数据库加载存储的数据（需自行实现）
    salt, stored_encrypted_hash, aes_key = server_store_password(decrypted_password)
    
    # 解密存储的哈希并验证
    decrypted_hash = decrypt_data(aes_key, stored_encrypted_hash)
    return verify_password(decrypted_hash, salt, input_password)

# ------------------- 测试流程 -------------------
# 服务端注册并返回公钥
public_key_pem = register()

# 客户端加密密码
encrypted_password = client_encrypt_password(public_key_pem, "my_password")

# 服务端验证登录（模拟）
with open("private_key.pem", "rb") as f:
    private_key_pem = f.read()

is_valid = login(private_key_pem, encrypted_password, "my_password")
print("登录成功:", is_valid)  # 应输出 True