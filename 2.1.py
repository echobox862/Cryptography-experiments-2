from hashlib import sha1
from base64 import b64decode
from Crypto.Cipher import AES


def solve_check_digit(k_str):
    """
    根据校验规则计算并填充K中的校验位（替换'?'）
    
    规则（文献[2]）：
    1. 取K中索引21-26的6个数字字符
    2. 分别与权重[7, 3, 1, 7, 3, 1]相乘后求和
    3. 求和结果对10取模，得到校验位，填充到索引27的位置（原'?'处）
    
    参数:
        k_str: 初始密钥字符串，包含待填充的'?'（长度固定，索引27为'?'）
    
    返回:
        str: 填充校验位后的完整密钥字符串
    """
    k_list = list(k_str)
    weights = [7, 3, 1, 7, 3, 1]  # 校验位计算权重
    checksum = 0
    
    # 计算索引21-26的数字与对应权重的乘积和
    for i in range(21, 27):
        # 转换字符为整数后与权重相乘，累加和
        checksum = (checksum + int(k_list[i]) * weights[i - 21]) % 10
    
    # 填充校验位到索引27（替换'?'）
    k_list[27] = str(checksum)
    return ''.join(k_list)


def generate_k_seed(k_str):
    """
    从完整密钥字符串中提取特定字段，生成K_seed（用于后续密钥推导）
    
    提取规则:
    取K中的 [0-9] + [13-19] + [21-27] 部分拼接，计算SHA1哈希后取前32位
    
    参数:
        k_str: 经solve_check_digit处理后的完整密钥字符串
    
    返回:
        str: K_seed（32位十六进制字符串）
    """
    # 提取指定片段并拼接（mrz_imt字段）
    mrz_imt = k_str[:10] + k_str[13:20] + k_str[21:28]
    # 计算SHA1哈希（十六进制形式），取前32位作为K_seed
    sha1_hash = sha1(mrz_imt.encode()).hexdigest()
    return sha1_hash[:32]


def add_even_parity(hex_str):
    """
    对十六进制字符串添加偶校验位，生成8位字节序列（每7位数据+1位校验位）
    
    偶校验规则:
    1. 将十六进制字符串转换为二进制字符串（去除前缀'0b'）
    2. 每7位二进制为一组，计算组内'1'的个数
    3. 若'1'的个数为偶数，添加'1'作为校验位；否则添加'0'，确保每组8位中'1'的总数为奇数
    
    参数:
        hex_str: 待处理的十六进制字符串
    
    返回:
        str: 添加校验位后的十六进制字符串
    """
    # 十六进制转二进制字符串（去除'0b'前缀）
    binary_str = bin(int(hex_str, 16))[2:]
    parity_result = []
    
    # 每7位一组处理
    for i in range(0, len(binary_str), 7):
        # 提取当前7位数据（最后一组可能不足7位，直接处理）
        data_seven = binary_str[i:i+7]
        # 计算当前组'1'的个数
        one_count = data_seven.count('1')
        # 添加偶校验位：1的个数为偶数则补'1'，否则补'0'
        parity_bit = '1' if (one_count % 2 == 0) else '0'
        parity_result.append(data_seven)
        parity_result.append(parity_bit)
    
    # 拼接所有带校验位的二进制，转回十六进制（去除'0x'前缀）
    full_binary = ''.join(parity_result)
    return hex(int(full_binary, 2))[2:]


def derive_aes_key(k_seed):
    """
    从K_seed推导AES加密密钥
    
    推导步骤:
    1. K_seed后拼接'00000001'
    2. 计算拼接后字符串的SHA1哈希（32位十六进制）
    3. 哈希值前16位和后16位分别通过add_even_parity处理，拼接得到最终密钥
    
    参数:
        k_seed: 由generate_k_seed生成的32位十六进制字符串
    
    返回:
        str: AES密钥（十六进制字符串）
    """
    # 拼接固定后缀'00000001'
    seed_with_suffix = k_seed + '00000001'
    # 计算SHA1哈希（32位十六进制）
    sha1_hash = sha1(bytes.fromhex(seed_with_suffix)).hexdigest()
    # 前16位和后16位分别添加校验位后拼接
    ka = add_even_parity(sha1_hash[:16])
    kb = add_even_parity(sha1_hash[16:32])
    return ka + kb


def decrypt_ciphertext(ciphertext_b64, aes_key_hex):
    """
    使用AES-CBC模式解密Base64编码的密文
    
    解密参数:
    - 模式：CBC（Cipher Block Chaining）
    - 初始向量（IV）：32个'0'组成的十六进制字符串（16字节）
    - 密钥：由derive_aes_key生成的AES密钥（十六进制）
    
    参数:
        ciphertext_b64: Base64编码的密文字符串
        aes_key_hex: 十六进制格式的AES密钥
    
    返回:
        str: 解密后的明文字符串
    """
    # Base64解码密文
    ciphertext_bytes = b64decode(ciphertext_b64)
    # 初始向量（IV）：16字节全0（32个'0'的十六进制）
    iv = bytes.fromhex('0' * 32)
    # 初始化AES-CBC解密器
    aes_cipher = AES.new(bytes.fromhex(aes_key_hex), AES.MODE_CBC, iv)
    # 解密并转换为字符串
    plaintext_bytes = aes_cipher.decrypt(ciphertext_bytes)
    return plaintext_bytes.decode()


if __name__ == '__main__':
    # 初始参数
    CIPHERTEXT = '9MgYwmuPrjiecPMx61O6zIuy3MtIXQQ0E59T3xB6u0Gyf1gYs2i3K9Jxaa0zj4gTMazJuApwd6+jdyeI5iGHvhQyDHGVlAuYTgJrbFDrfB22Fpil2NfNnWFBTXyf7SDI'
    INITIAL_KEY = '12345678<8<<<1110182<111116?<<<<<<<<<<<<<<<4'
    
    # 步骤1：计算并填充校验位，得到完整K
    full_key = solve_check_digit(INITIAL_KEY)
    
    # 步骤2：生成K_seed
    k_seed = generate_k_seed(full_key)
    
    # 步骤3：推导AES密钥
    aes_key = derive_aes_key(k_seed)
    
    # 步骤4：解密得到明文
    plaintext = decrypt_ciphertext(CIPHERTEXT, aes_key)
    
    # 输出结果
    print(plaintext)