import os
import random
from Crypto.Cipher import AES


def generate_random_key() -> bytes:
    """生成16字节的随机AES密钥。"""
    return os.urandom(16)


def generate_random_padding() -> bytes:
    """生成5-10字节的随机填充字节。"""
    return os.urandom(random.randint(5, 10))


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


def encryption_oracle(key: bytes, message: bytes) -> tuple[bytes, int]:
    """
    随机选择AES-ECB或CBC模式加密消息，添加随机前后缀并填充。
    
    参数:
        key: AES加密密钥
        message: 需要加密的明文消息
    
    返回:
        二元组 (加密后的密文, 加密模式[AES.MODE_ECB或AES.MODE_CBC])
    """
    # 随机选择加密模式
    mode = random.choice([AES.MODE_ECB, AES.MODE_CBC])
    # 拼接随机前缀、消息、随机后缀
    plaintext = generate_random_padding() + message + generate_random_padding()
    # 填充至块大小
    plaintext_padded = pad(plaintext, 16)
    
    # 按选择的模式加密
    if mode == AES.MODE_ECB:
        cipher = AES.new(key, mode)
        return cipher.encrypt(plaintext_padded), mode
    else:  # AES.MODE_CBC
        iv = generate_random_key()  # 随机IV
        cipher = AES.new(key, mode, iv)
        return cipher.encrypt(plaintext_padded), mode


def detect_encryption_mode(ciphertext: bytes) -> int:
    """
    检测密文使用的AES加密模式（ECB或CBC）。
    
    原理: ECB模式会对相同明文块生成相同密文块，CBC模式不会。
    
    参数:
        ciphertext: 待检测的密文
    
    返回:
        检测出的模式[AES.MODE_ECB或AES.MODE_CBC]
    """
    # 按16字节拆分密文块
    blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
    # 若存在重复块则为ECB模式，否则为CBC模式
    if len(blocks) != len(set(blocks)):
        return AES.MODE_ECB
    return AES.MODE_CBC


# 测试检测准确率
key = generate_random_key()
test_message = b"\x00" * 16 * 3  # 构造包含重复块的明文（利于ECB检测）
total_tests = 1000
successful_detections = 0

# 多次测试
for _ in range(total_tests):
    ciphertext, actual_mode = encryption_oracle(key, test_message)
    detected_mode = detect_encryption_mode(ciphertext)
    if detected_mode == actual_mode:
        successful_detections += 1

# 输出准确率
accuracy = successful_detections / total_tests
print(f"检测准确率: {accuracy:.2%}")