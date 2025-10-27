import Crypto.Cipher.AES as AES
import os

# 生成16字节随机密钥（AES-128）
key = os.urandom(16)


def pad(message: bytes, block_size: int) -> bytes:
    """
    对字节消息进行PKCS#7填充，使其长度为块大小的整数倍。
    
    参数:
        message: 需要填充的字节消息
        block_size: 块大小（填充后的消息长度需为该值的整数倍）
    
    返回:
        填充后的字节消息
    """
    padding_length = block_size - len(message) % block_size
    return message + bytes([padding_length] * padding_length)


def unpad(message_padded: bytes) -> bytes:
    """
    去除字节消息的PKCS#7填充，验证填充的合法性。
    
    参数:
        message_padded: 带有PKCS#7填充的字节消息
    
    返回:
        去除填充后的原始字节消息
    
    异常:
        AssertionError: 若填充不合法
    """
    padding_length = message_padded[-1]
    message, padding = message_padded[:-padding_length], message_padded[-padding_length:]
    assert all(byte == padding_length for byte in padding), "无效的PKCS#7填充"
    return message


def AES_CBC_encrypt(userdata: bytes) -> bytes:
    """
    使用AES-CBC模式加密用户数据，会对用户数据进行特殊字符转义并拼接固定前后缀。
    
    参数:
        userdata: 用户输入的字节数据
    
    返回:
        加密后的字节密文（包含随机IV的加密结果）
    """
    # 转义用户数据中的分号和等号，避免注入
    escaped_userdata = userdata.replace(b";", b"%3B").replace(b"=", b"%3D")
    # 拼接完整明文（前缀 + 转义后用户数据 + 后缀）
    data = (
        b"comment1=cooking MCs;userdata="
        + escaped_userdata
        + b";comment2= like a pound of bacon"
    )
    # 前置16字节空数据，生成随机IV，加密并返回
    plaintext = pad((b"\x00" * 16) + data, 16)
    cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))  # 随机IV
    return cipher.encrypt(plaintext)


def AES_CBC_decrypt(data: bytes) -> dict:
    """
    使用AES-CBC模式解密密文，并将解密结果解析为键值对字典。
    
    参数:
        data: 需要解密的字节密文
    
    返回:
        解析后的键值对字典
    """
    # 使用随机IV解密（实际应与加密IV一致，此处代码保持原逻辑）
    cipher = AES.new(key, AES.MODE_CBC, os.urandom(16))
    decrypted_padded = cipher.decrypt(data)
    # 去除填充并截断前置16字节空数据
    decrypted = unpad(decrypted_padded)[16:]
    # 解析为键值对字典
    return {
        (kv := item.split(b"=", maxsplit=1))[0].decode(): kv[1]
        for item in decrypted.split(b";")
    }


def is_admin(data: bytes) -> bool:
    """
    检测解密后的密文中是否包含admin=true的键值对。
    
    参数:
        data: 加密后的字节密文
    
    返回:
        若包含admin=true则返回True，否则返回False
    """
    decrypted = AES_CBC_decrypt(data)
    return decrypted.get("admin") == b"true"


# 比特翻转攻击：构造恶意用户数据并修改密文实现权限提升
pad_length = 2
userdata = b"A" * pad_length + b":admin<true"  # 待翻转的特殊字符
encrypted = bytearray(AES_CBC_encrypt(userdata))

# 翻转密文特定位置的比特，将:转为;、<转为=
encrypted[pad_length + 30] ^= ord(":") ^ ord(";")
encrypted[pad_length + 36] ^= ord("<") ^ ord("=")

# 检测攻击是否成功
if is_admin(encrypted):
    print("Success!")
else:
    print("Fail!")