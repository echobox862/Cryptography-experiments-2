from Crypto.Cipher import AES
from base64 import b64decode

# 提醒：需先安装依赖库 pycryptodome（AES 加密依赖），安装命令：pip install pycryptodome


def pkcs7_pad(message: bytes, block_size: int) -> bytes:
    """
    遵循 PKCS#7 标准为字节消息添加填充，确保消息长度为指定块大小的整数倍（适配分组加密）
    
    PKCS#7 填充规则：
    1. 计算填充长度 = 块大小 - (消息长度 % 块大小)
    2. 生成填充内容：由“填充长度”对应的字节值重复“填充长度”次（例：需填充4字节则添加 b'\x04\x04\x04\x04'）
    
    参数:
        message: 待填充的原始消息（bytes 类型，如明文或待加密数据）
        block_size: 分组加密的块大小（AES 固定为 16 字节，即 AES.block_size）
    
    返回:
        bytes: 已添加 PKCS#7 填充的消息，长度为 block_size 的整数倍
    """
    # 计算需补充的填充字节数
    padding_length = block_size - (len(message) % block_size)
    # 生成填充字节并拼接到原始消息
    padded_message = message + bytes([padding_length]) * padding_length
    return padded_message


def pkcs7_unpad(padded_message: bytes) -> bytes:
    """
    去除遵循 PKCS#7 标准填充的消息中的填充部分，恢复原始消息
    
    去填充规则：
    1. 取填充后消息的最后一个字节，其值即为填充长度（如最后一字节是 \x04，说明填充了4字节）
    2. 从消息末尾截取掉“填充长度”对应的字节，得到原始消息
    
    参数:
        padded_message: 已添加 PKCS#7 填充的消息（bytes 类型，如解密后的带填充明文）
    
    返回:
        bytes: 去除填充后的原始消息
    
    注意:
        若输入消息未遵循 PKCS#7 规则（如最后一字节值大于消息总长度），可能抛出索引越界异常
    """
    # 提取最后一个字节作为填充长度
    padding_length = padded_message[-1]
    # 截取掉末尾的填充字节，返回原始消息
    original_message = padded_message[:-padding_length]
    return original_message


def aes_ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    使用 AES-ECB（电子密码本）模式加密明文，自动添加 PKCS#7 填充
    
    ECB 模式特点：
    - 将明文分块（每块 16 字节），每块独立用 AES 加密，无初始向量（IV）
    - 安全性较低（相同明文块加密后结果相同），仅适合简单测试场景
    
    参数:
        plaintext: 待加密的明文字节（bytes 类型）
        key: AES 密钥（bytes 类型，需符合 AES 密钥长度规范：16 字节=AES-128、24 字节=AES-192、32 字节=AES-256）
    
    返回:
        bytes: AES-ECB 加密后的密文字节
    """
    # 初始化 AES-ECB 加密器（ECB 模式无需 IV）
    cipher = AES.new(key, AES.MODE_ECB)
    # 先填充明文至块大小整数倍，再加密
    padded_plaintext = pkcs7_pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_plaintext)


def aes_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    """
    使用 AES-ECB（电子密码本）模式解密密文，返回带 PKCS#7 填充的明文
    
    参数:
        ciphertext: 待解密的密文字节（bytes 类型，长度需为 16 字节的整数倍）
        key: AES 密钥（bytes 类型，需与加密时使用的密钥完全一致）
    
    返回:
        bytes: 解密后带 PKCS#7 填充的明文字节（需后续调用 pkcs7_unpad 去填充）
    """
    # 初始化 AES-ECB 解密器
    cipher = AES.new(key, AES.MODE_ECB)
    # 解密（ECB 模式直接解密，密文需为块大小整数倍）
    padded_plaintext = cipher.decrypt(ciphertext)
    return padded_plaintext


def bytes_xor(a: bytes, b: bytes) -> bytes:
    """
    对两个等长字节数组进行按位异或运算，返回结果字节数组
    
    异或规则：对应位均为 0 或均为 1 时结果为 0，否则为 1（即 x ^ y）
    
    参数:
        a: 第一个输入字节数组（bytes 类型）
        b: 第二个输入字节数组（bytes 类型，需与 a 长度相同）
    
    返回:
        bytes: 按位异或后的结果字节数组
    
    注意:
        若输入字节数组长度不同，zip 会自动截断至较短长度，建议确保输入等长
    """
    return bytes(x ^ y for x, y in zip(a, b))


def aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    使用 AES-CBC（密码分组链接）模式加密明文，手动实现分块逻辑，基于 ECB 模式扩展
    
    CBC 加密流程：
    1. 对明文添加 PKCS#7 填充，确保长度为 16 字节整数倍
    2. 初始化“前一个密文块”为初始向量（IV），IV 需与块大小（16 字节）相同
    3. 遍历明文块：
       - 当前明文块与“前一个密文块”异或
       - 异或结果用 AES-ECB 加密，得到当前密文块
       - 更新“前一个密文块”为当前密文块，拼接所有密文块
    
    参数:
        plaintext: 待加密的明文字节（bytes 类型）
        key: AES 密钥（bytes 类型，16/24/32 字节，与 ECB 模式要求一致）
        iv: 初始向量（bytes 类型，必须为 16 字节，加密/解密需使用相同 IV）
    
    返回:
        bytes: AES-CBC 加密后的密文字节（长度为 16 字节整数倍）
    """
    # 初始化密文结果、前一个块（初始为 IV）
    ciphertext = b""
    prev_block = iv
    # 明文添加 PKCS#7 填充
    padded_plaintext = pkcs7_pad(plaintext, AES.block_size)
    
    # 按块处理明文（每块 16 字节）
    for i in range(0, len(padded_plaintext), AES.block_size):
        # 提取当前明文块
        current_plaintext_block = padded_plaintext[i:i + AES.block_size]
        # 明文块与前一个密文块（初始为 IV）异或
        xor_result = bytes_xor(current_plaintext_block, prev_block)
        # 异或结果用 ECB 加密，得到当前密文块
        current_ciphertext_block = aes_ecb_encrypt(xor_result, key)
        # 拼接密文块，更新前一个块为当前密文块
        ciphertext += current_ciphertext_block
        prev_block = current_ciphertext_block
    
    return ciphertext


def aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    使用 AES-CBC（密码分组链接）模式解密密文，手动实现分块逻辑，基于 ECB 模式扩展
    
    CBC 解密流程：
    1. 初始化“前一个密文块”为初始向量（IV），IV 需与加密时一致
    2. 遍历密文块（每块 16 字节）：
       - 当前密文块用 AES-ECB 解密，得到中间结果
       - 中间结果与“前一个密文块”异或，得到当前明文块
       - 更新“前一个密文块”为当前密文块，拼接所有明文块
    3. 返回带 PKCS#7 填充的明文（需后续去填充）
    
    参数:
        ciphertext: 待解密的密文字节（bytes 类型，长度需为 16 字节整数倍）
        key: AES 密钥（bytes 类型，需与加密时完全一致）
        iv: 初始向量（bytes 类型，需与加密时完全一致，16 字节）
    
    返回:
        bytes: 解密后带 PKCS#7 填充的明文字节（需调用 pkcs7_unpad 恢复原始明文）
    """
    # 初始化明文结果、前一个块（初始为 IV）
    plaintext = b""
    prev_block = iv
    
    # 按块处理密文（每块 16 字节）
    for i in range(0, len(ciphertext), AES.block_size):
        # 提取当前密文块
        current_ciphertext_block = ciphertext[i:i + AES.block_size]
        # 密文块用 ECB 解密，得到中间结果
        ecb_decrypt_result = aes_ecb_decrypt(current_ciphertext_block, key)
        # 中间结果与前一个密文块（初始为 IV）异或，得到当前明文块
        current_plaintext_block = bytes_xor(ecb_decrypt_result, prev_block)
        # 拼接明文块，更新前一个块为当前密文块
        plaintext += current_plaintext_block
        prev_block = current_ciphertext_block
    
    return plaintext


if __name__ == "__main__":
    # -------------------------- 解密配置参数 --------------------------
    # AES-CBC 初始向量（IV）：16 字节全 0（与加密时 IV 需一致）
    iv = b'\x00' * AES.block_size  # AES.block_size = 16，故 IV 为 b'\x00'*16
    # AES 密钥：16 字节（AES-128），与加密时密钥一致
    key = b'YELLOW SUBMARINE'  # 字节长度 16，符合 AES-128 密钥规范
    # 密文文件路径：需与脚本同目录，文件内容为 base64 编码的 AES-CBC 密文
    ciphertext_file = "10.txt"

    # -------------------------- 执行解密流程 --------------------------
    try:
        # 读取 base64 编码的密文并解码
        with open(ciphertext_file, "r", encoding="utf-8") as f:
            base64_ciphertext = f.read().strip()  # 去除文件内容首尾空白（如换行符）
        ciphertext = b64decode(base64_ciphertext)  # base64 解码为密文字节

        # AES-CBC 解密（返回带 PKCS#7 填充的明文）
        padded_plaintext = aes_cbc_decrypt(ciphertext, key, iv)
        # 去除 PKCS#7 填充，恢复原始明文
        original_plaintext = pkcs7_unpad(padded_plaintext)
        # 解码为字符串并输出（rstrip() 去除可能的尾部空白，保持原代码输出习惯）
        print("AES-CBC 解密结果：")
        print(original_plaintext.decode().rstrip())

    except FileNotFoundError:
        print(f"错误：文件 '{ciphertext_file}' 未找到，请确保文件与脚本在同一目录！")
    except ValueError as e:
        print(f"解密错误：{e}（可能是密钥、IV 错误或密文格式异常）")
    except Exception as e:
        print(f"未知错误：{e}")