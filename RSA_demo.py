#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Created by miaoshuijian on 2017/9/11

"""
create_rsa_key() - 创建RSA密钥
my_encrypt_and_decrypt() - 加密解密测试
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP


def create_rsa_key(password="123456"):
    """
    创建RSA密钥
    步骤说明：
    1、从 Crypto.PublicKey 包中导入 RSA，创建一个密码
    2、生成 1024/2048 位的 RSA 密钥
    3、调用 RSA 密钥实例的 exportKey 方法，传入密码、使用的 PKCS 标准以及加密方案这三个参数。
    4、将私钥写入磁盘的文件。
    5、使用方法链调用 publickey 和 exportKey 方法生成公钥，写入磁盘上的文件。
    """

    key = RSA.generate(1024)
    encrypted_key = key.exportKey(passphrase=password, pkcs=8,
                                  protection="scryptAndAES128-CBC")
    with open("keyPairs/my_private_rsa_key.bin", "wb") as f:
        f.write(encrypted_key)
    with open("keyPairs/my_rsa_public.pem", "wb") as f:
        f.write(key.publickey().exportKey())


def encrypt_and_decrypt_test(password="123456"):
    # 加载公钥
    recipient_key = RSA.import_key(
        open("keyPairs/my_rsa_public.pem").read()
    )
    cipher_rsa = PKCS1_v1_5.new(recipient_key)

    en_data = cipher_rsa.encrypt(b"123456")
    print(len(en_data), en_data)

    # 读取密钥
    private_key = RSA.import_key(
        open("keyPairs/my_private_rsa_key.bin").read(),
        passphrase=password
    )
    cipher_rsa = PKCS1_v1_5.new(private_key)
    data = cipher_rsa.decrypt(en_data, None)

    print(data)


if __name__ == '__main__':
    # create_rsa_key()
    encrypt_and_decrypt_test()
