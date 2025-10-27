import base64
import os
import string
import random
from Crypto.Cipher import AES

# 生成随机长度（0-64字节）的前缀
prefix_length = random.randint(0, 64)
prefix = os.urandom(prefix_length)

# 目标未知字符串（Base64解码后）
TARGET_B64 = """
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
"""
unknown_string = base64.b64decode(TARGET_B64)


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


def AES_ECB_encrypt(control_text: bytes) -> bytes:
    """
    使用AES-ECB模式加密拼接后的明文（前缀 + 控制文本 + 未知字符串）。
    
    参数:
        control_text: 可控的输入文本（字节类型）
    
    返回:
        加密后的字节密文
    """
    key = os.urandom(16)  # 随机16字节密钥
    # 拼接明文并填充
    plaintext = pad(prefix + control_text + unknown_string, 16)
    return AES.new(key, AES.MODE_ECB).encrypt(plaintext)


def get_unknown_params() -> tuple[int, int, int]:
    """
    推断未知字符串长度、前缀导致的偏移量和需要的补齐长度。
    
    返回:
        三元组 (未知字符串长度, 前缀偏移量, 补齐长度)
    """
    # 初始加密长度（无控制文本时）
    initial_length = len(AES_ECB_encrypt(b""))
    unknown_length = initial_length
    
    # 确定未知字符串长度（通过添加不同长度A观察加密长度变化）
    for i in range(16):
        if len(AES_ECB_encrypt(b"A" * i)) != initial_length:
            unknown_length = initial_length - i
            break
    
    # 确定前缀偏移和补齐长度（通过寻找重复块）
    padding_length = 0
    while True:
        padding_length += 1
        ciphertext = AES_ECB_encrypt(b"A" * padding_length)
        # 按16字节拆分块
        blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
        # 检测重复块（ECB模式特性）
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return (unknown_length - i * 16 + padding_length % 16,
                        i * 16,
                        padding_length % 16)


# 获取未知参数
unknown_str_length, offset, left_pad_length = get_unknown_params()
left_pad = b"\x00" * left_pad_length  # 补齐前缀到块边界的填充
plain_chars = string.printable.encode()  # 可能的明文字符集


def recover_plaintext(known_text: bytes) -> bool:
    """
    深度优先搜索恢复未知字符串明文。
    
    参数:
        known_text: 已恢复的明文部分
    
    返回:
        若成功恢复完整明文则返回True，否则返回False
    """
    while True:
        # 构造15字节的部分已知文本（用于猜测下一个字符）
        partial = known_text[-15:] if len(known_text) >= 15 else known_text
        partial = b"\x00" * (15 - len(partial)) + partial
        
        # 尝试所有可能的字符
        candidates = []
        for char in plain_chars:
            # 构造查询文本：补齐前缀 + 部分已知文本 + 待测试字符 + 填充
            query = left_pad + partial + bytes([char]) + b"\x00" * (15 - len(known_text) % 16)
            ciphertext = AES_ECB_encrypt(query)[offset:]  # 截取有效密文部分
            
            # 对比密文块判断字符是否正确
            target_block_idx = len(known_text) // 16
            if ciphertext[15] == ciphertext[target_block_idx * 16 + 31]:
                candidates.append(char)
        
        # 处理候选字符
        if len(candidates) == 1:
            known_text += bytes(candidates)
            # 恢复完成
            if len(known_text) == unknown_str_length:
                print(known_text.decode())
                return True
            continue
        elif len(known_text) == unknown_str_length:
            print(known_text.decode())
            return True
        elif len(candidates) == 0:
            return False
        else:
            # 多候选时递归尝试
            for c in candidates:
                if recover_plaintext(known_text + bytes([c])):
                    return True
    return False


# 从空字符串开始恢复明文
recover_plaintext(b"")