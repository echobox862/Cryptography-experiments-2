def pad(message: bytes, block_size: int) -> bytes:
    """
    对字节消息进行PKCS#7填充，使其长度为块大小的整数倍。
    
    参数:
        message: 需要填充的字节消息
        block_size: 块大小（填充后的消息长度需为该值的整数倍）
    
    返回:
        填充后的字节消息，末尾添加n个值为n的字节（n为需要填充的长度）
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
        AssertionError: 若填充不合法（填充字节值与填充长度不一致）
    """
    padding_length = message_padded[-1]
    # 分离原始消息和填充部分
    message, padding = message_padded[:-padding_length], message_padded[-padding_length:]
    # 验证所有填充字节的值是否等于填充长度
    assert all(byte == padding_length for byte in padding), "无效的PKCS#7填充"
    return message


# 测试合法填充
print(unpad(b"ICE ICE BABY\x04\x04\x04\x04"))
# 测试非法填充（会触发断言错误）
print(unpad(b"ICE ICE BABY\x05\x05\x05\x05"))