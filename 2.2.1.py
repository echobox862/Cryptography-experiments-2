def pkcs7_pad(message: bytes, block_size: int) -> bytes:
    """
    遵循PKCS#7标准为字节消息添加填充，确保消息长度为指定块大小的整数倍
    
    PKCS#7填充规则：
    1. 计算填充长度：block_size - (消息长度 % block_size)
    2. 生成填充内容：由填充长度值组成的字节，重复填充长度次
    （例：消息长度比block_size少4，则填充4个\x04字节）
    
    参数:
        message: 待添加填充的原始消息（bytes类型）
        block_size: 加密算法的块大小（如AES常用16、32字节，需为正整数）
    
    返回:
        bytes: 已添加PKCS#7填充的消息，长度为block_size的整数倍
    """
    # 计算需要补充的填充长度
    padding_length = block_size - (len(message) % block_size)
    # 生成填充字节（填充长度值重复padding_length次），拼接到原始消息后
    padded_message = message + bytes([padding_length]) * padding_length
    return padded_message


def pkcs7_unpad(padded_message: bytes) -> bytes:
    """
    去除遵循PKCS#7标准填充的消息中的填充部分，恢复原始消息
    
    去填充规则：
    1. 取填充后消息的最后一个字节，该字节的值即为填充长度
    2. 从消息末尾截取掉填充长度对应的字节，得到原始消息
    
    参数:
        padded_message: 已添加PKCS#7填充的消息（bytes类型）
    
    返回:
        bytes: 去除填充后的原始消息
    
    注意:
        若输入消息未遵循PKCS#7填充规则（如最后一个字节值大于消息长度），可能抛出索引异常
    """
    # 提取最后一个字节作为填充长度
    padding_length = padded_message[-1]
    # 截取掉末尾的填充字节，返回原始消息
    original_message = padded_message[:-padding_length]
    return original_message


# 测试示例：为"YELLOW SUBMARINE"添加16字节块大小的PKCS#7填充，再去除填充
if __name__ == "__main__":
    # 原始测试消息（字节类型）
    test_message = b'YELLOW SUBMARINE'
    # 指定块大小（如AES的16字节块大小）
    test_block_size = 16
    
    # 步骤1：添加PKCS#7填充
    padded_message = pkcs7_pad(test_message, test_block_size)
    print("添加PKCS#7填充后的消息（字节形式）:")
    print(padded_message)  # 输出：b'YELLOW SUBMARINE\x04\x04\x04\x04'
    
    # 步骤2：去除PKCS#7填充
    unpadded_message = pkcs7_unpad(padded_message)
    print("\n去除填充后的原始消息（字节形式）:")
    print(unpadded_message)  # 输出：b'YELLOW SUBMARINE'