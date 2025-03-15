from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import hashlib
import os

# ------------------- 密钥管理 -------------------
def load_or_generate_private_key(private_key_path="private_key.pem"):
    """加载或生成RSA私钥"""
    if os.path.exists(private_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(private_key_path, "wb") as f:
            f.write(private_key_pem)
    return private_key

def get_public_key_pem(private_key):
    """从私钥获取公钥PEM"""
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# ------------------- 加密/解密 -------------------
def client_encrypt_data(public_key_pem: bytes, data: str) -> bytes:
    """客户端加密数据（RSA）"""
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    return public_key.encrypt(
        hash1(data.encode("utf-8")),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def server_decrypt_data(private_key, encrypted_data: bytes) -> str:
    """服务端解密数据（RSA）"""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ------------------- 密码哈希 -------------------
def hash1 (password: str) -> bytes:
    """哈希密码"""
    return hashlib.sha512(password).digest()
def hash_password(password: str, salt: bytes) -> bytes:
    """使用盐值哈希密码"""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        100000  # 推荐迭代次数
    )

def verify_password(stored_hash: bytes, salt: bytes, input_password: str) -> bool:
    """验证密码"""
    input_hash = hash_password(input_password, salt)
    return input_hash == stored_hash

# ------------------- 数据库模拟 -------------------
class Database:
    def __init__(self):
        self.store = {}
    
    def store_user(self, label: str, salt: bytes, hashed_password: bytes):
        self.store[label] = (salt, hashed_password)
    
    def get_user(self, label: str):
        return self.store.get(label, (None, None))

db = Database()

# ------------------- 服务端逻辑 -------------------
def server_register(private_key, label,encrypted_data):
    """处理注册请求"""
    try:
        # 解密数据
        password = server_decrypt_data(private_key, encrypted_data)
        
        # 生成盐值并哈希密码
        salt = os.urandom(16)
        hashed_password = hash_password(password, salt)
        
        # 存储到数据库
        db.store_user(label, salt, hashed_password)
        return True
    except Exception as e:
        print(f"注册失败: {str(e)}")
        return False

def server_login(private_key, label,encrypted_data: bytes):
    """处理登录请求"""
    try:
        password = server_decrypt_data(private_key, encrypted_data)
        # 获取存储的盐值和哈希
        salt, stored_hash = db.get_user(label)
        if salt is None:
            return False  # 用户不存在
        return verify_password(stored_hash, salt, password)
    except Exception as e:
        print(f"登录失败: {str(e)}")
        return False

# ------------------- 测试流程 -------------------
private_key = load_or_generate_private_key()
public_key_pem = get_public_key_pem(private_key)
if __name__ == "__main__":
    # 初始化密钥


    # 模拟客户端注册
    label = "Liming"
    password = "man! what can I say!"
    encrypted_register = client_encrypt_data(public_key_pem,password)
    # 服务端处理注册
    if server_register(private_key,label, encrypted_register):
        print("注册成功")
    
    # 模拟客户端登录
    encrypted_login = client_encrypt_data(public_key_pem,password)
    
    # 服务端验证登录
    login_result = server_login(private_key,label, encrypted_login)
    print(f"登录结果: {login_result}")