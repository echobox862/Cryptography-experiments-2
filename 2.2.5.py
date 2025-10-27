from Crypto.Cipher import AES
from Crypto import Random


def pad(message: bytes, block_size: int) -> bytes:
    """
    对字节消息进行PKCS#7填充。
    
    参数:
        message: 需要填充的字节消息
        block_size: 块大小
    
    返回:
        填充后的字节消息
    """
    padding_length = block_size - len(message) % block_size
    return message + bytes([padding_length] * padding_length)


def unpad(message: bytes) -> bytes:
    """
    去除字节消息的PKCS#7填充。
    
    参数:
        message: 带有填充的字节消息
    
    返回:
        去除填充后的原始消息
    """
    padding_length = message[-1]
    return message[:-padding_length]


def AES_ECB_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    使用AES-ECB模式加密明文。
    
    参数:
        plaintext: 待加密的明文
        key: AES加密密钥
    
    返回:
        加密后的密文
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def AES_ECB_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    使用AES-ECB模式解密密文。
    
    参数:
        ciphertext: 待解密的密文
        key: AES解密密钥
    
    返回:
        解密后的明文（包含填充）
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def profile_for(email: str) -> dict:
    """
    根据邮箱生成用户资料字典，过滤特殊字符&和=。
    
    参数:
        email: 用户邮箱字符串
    
    返回:
        包含email、uid、role的用户资料字典
    """
    # 过滤特殊字符，防止注入
    sanitized_email = email.replace('&', '').replace('=', '')
    return {'email': sanitized_email, 'uid': 10, 'role': 'user'}


def kv_encode(dict_obj: dict) -> str:
    """
    将键值对字典编码为"key1=value1&key2=value2"格式的字符串。
    
    参数:
        dict_obj: 待编码的字典
    
    返回:
        编码后的字符串
    """
    encoded_parts = []
    for key, value in dict_obj.items():
        encoded_parts.append(f"{key}={value}")
    return '&'.join(encoded_parts)


def kv_decode(encoded_str: str) -> dict:
    """
    将"key1=value1&key2=value2"格式的字符串解码为字典。
    
    参数:
        encoded_str: 待解码的字符串
    
    返回:
        解码后的键值对字典
    """
    decoded_dict = {}
    for part in encoded_str.split('&'):
        key, value = part.split('=')
        decoded_dict[key] = value
    return decoded_dict


class ECBOracle:
    """AES-ECB模式加解密预言机，内部维护随机密钥。"""
    
    def __init__(self):
        """初始化预言机，生成随机AES密钥。"""
        self.key = Random.new().read(AES.key_size[0])  # 16字节密钥
    
    def encrypt(self, email: str) -> bytes:
        """
        加密用户资料：根据邮箱生成资料并加密。
        
        参数:
            email: 用户邮箱字符串
        
        返回:
            加密后的密文
        """
        # 生成资料并编码为字符串
        profile = profile_for(email)
        encoded_profile = kv_encode(profile)
        # 转换为字节并加密
        return AES_ECB_encrypt(encoded_profile.encode(), self.key)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        解密密文并去除填充。
        
        参数:
            ciphertext: 待解密的密文
        
        返回:
            解密后的原始字节明文
        """
        decrypted_padded = AES_ECB_decrypt(ciphertext, self.key)
        return unpad(decrypted_padded)


def cut_and_paste_attack(oracle: ECBOracle) -> bytes:
    """
    实施cut-and-paste攻击，构造包含role=admin的恶意密文。
    
    参数:
        oracle: ECB加密预言机
    
    返回:
        恶意构造的密文
    """
    block_size = AES.block_size
    # 计算前缀长度（使"email=" + 前缀 恰好填满一个块）
    prefix_length = block_size - len('email=')
    # 计算后缀填充长度（使"admin" + 填充 恰好填满一个块）
    suffix_pad_length = block_size - len('admin')
    suffix_pad = chr(suffix_pad_length) * suffix_pad_length
    
    # 构造第一个邮箱：生成包含"admin"的块
    email1 = 'x' * prefix_length + 'admin' + suffix_pad
    ciphertext1 = oracle.encrypt(email1)
    admin_block = ciphertext1[16:32]  # 提取包含"admin"的密文块
    
    # 构造第二个邮箱：生成前两部分密文（确保role在第三块）
    email2 = "master@xd.com"  # 使得编码后前两块为"email=master@xd.com&uid=10&role="
    ciphertext2 = oracle.encrypt(email2)
    prefix_blocks = ciphertext2[:32]  # 提取前两块密文
    
    # 拼接前两块密文和admin块，形成恶意密文
    return prefix_blocks + admin_block


# 执行攻击并验证结果
oracle = ECBOracle()
malicious_ciphertext = cut_and_paste_attack(oracle)

# 解密并解析结果
decrypted = oracle.decrypt(malicious_ciphertext).decode()
result = kv_decode(decrypted)
print(result)