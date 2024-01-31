from Crypto import Random

import binascii

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import argparse

parser = argparse.ArgumentParser(
    description="文件加密工具，可以对文件或文件夹下的文件进行加密，支持多种加密方式，-h查看帮助")
parser.add_argument('-f', '--file', type=str, required=False, help="指定加密的文件")
parser.add_argument('-d', '--dir', type=str, required=False, help="指定加密的文件夹")
parser.add_argument('-o', '--out', type=str, required=False, default="./", help="指定输出文件夹， 默认当前路径")
parser.add_argument('-k', '--key', type=str, required=False, help="加密密钥")
parser.add_argument('-kt', '--key_type', required=False, type=str, help="加密类型")
parser.add_argument('-gk', '--get_key', action='store_true', help="获取加密密钥")
parser.add_argument('-e', '--encrypto', action='store_true', help="进行加密操作，进行加密操作前你需要先获取加密密钥")
parser.add_argument('-de', '--decrypto', action='store_true', help="进行解密操作")
parser.add_argument('-kl', '--key_length', required=False, type=int, default=32,
                    help="加密密钥长度，可以为16,24,32，默认32")
args = parser.parse_args()


def get_files(dir_name):
    file_list = list()
    try:
        for root, dirs, files in os.walk(dir_name):
            # level = root.replace(dir_name, '').count(os.sep)
            # indent = ' ' * 4 * (level)
            # print(f'{indent}{os.path.basename(root)}/')
            for f in files:
                file_list.append(os.path.join(root, f))
                print('dir:%s get file:%s', dir_name, os.path.join(root, f))
            print('dir:%s get %s files', dir_name, len(file_list))
        return file_list
    except OSError as e:
        print(f"Error: {str(e)}")
        exit(-1)
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(-1)


def get_secret_key(length=256):
    secret_key = get_random_bytes(length)
    return secret_key


def decode_key(key_str):
    return binascii.unhexlify(key_str.encode())


def encrypt_file(key, in_filename, out_dir, chunksize=16 * 1024):
    iv = Random.new().read(AES.block_size)
    print(f"加密初始向量:{iv}")
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    out_filename = out_dir + os.sep + os.path.basename(in_filename) + '.encrypt'
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(iv)  # write IV at the very beginning of outfile
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    print("文件大小是16的整数倍，将填充16个额外字符")
                    chunk = pad(bytes(0), 16)  # 添加一个完整的填充块
                    print(f"填充的完整数据：{chunk}")
                    data = cipher.encrypt(chunk)  # 加密填充块
                    outfile.write(data)
                    break
                elif len(chunk) % 16 != 0:
                    print("文件大小不是16的整数倍，将填充额外字符")
                    chunk = pad(chunk, 16)
                    print(f"填充之后的完整数据：{chunk}")
                    data = cipher.encrypt(chunk)  # 加密填充块
                    outfile.write(data)
                    break
                else:
                    data = cipher.encrypt(chunk)
                    outfile.write(data)


def decrypto_file1(key, in_filename, out_dir, default_chunksize=16 * 1024):
    out_filename = out_dir + os.sep + os.path.basename(in_filename).replace('.encrypt', '')
    print(f"获取解密文件：{in_filename}")
    file_size = os.path.getsize(in_filename) - 16
    print(f"解密文件原始大小：{file_size}")
    chunksize = min(file_size, default_chunksize)
    if chunksize <= 0:
        print("文件为空,不进行解密")
        return
    print(f"读取的块大小：{chunksize}")

    if file_size < 32:
        with open(in_filename, 'rb') as f:
            iv = f.read(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            chunk = f.read()  # 一次性读取所有数据
            last_chunk = unpad(cipher.decrypt(chunk), 16)
            with open(out_filename, 'wb') as outf:
                outf.write(last_chunk)
            return
    with open(in_filename, 'rb') as infile:
        iv = infile.read(16)
        print(f"获取解密文件向量：{iv}")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(cipher.decrypt(chunk))
        with open(out_filename, 'rb+') as f:
            f.seek(-32, os.SEEK_END)  # -16, only deal with the last block
            chunk = f.read(32)
            print(f"最后一个chunksize: {chunk}")
            if len(chunk) == 17 and chunk[-1] == 16 and all(
                    b == 16 for b in chunk):  # if it's the padding block, discard it.
                f.seek(-16, os.SEEK_END)
                f.truncate()
            else:
                last_chunk = unpad(chunk, 16)
                print(f"最后一个chunksize去除填充后: {last_chunk}")
                f.seek(-16, os.SEEK_END)
                f.truncate()
                f.write(last_chunk)

    print("文件解密成功！")

def decrypto_file(key: bytes, in_filename: str, out_dir: str,
                  default_chunksize: int = 1024 * 1024):

    out_filename = out_dir + os.sep + os.path.basename(in_filename).replace('.encrypt', '')
    print(f"获取解密文件：{in_filename}")
    file_size = os.path.getsize(in_filename) - 16 # why minus 16?

    print(f"解密文件原始大小：{file_size}")

    chunksize = min(file_size, default_chunksize)
    if chunksize <= 0:
        print("文件为空,不进行解密")
        return
    print(f"读取的块大小：{chunksize}")

    with open(in_filename, 'rb') as infile:
        iv = infile.read(16)
        print(f"获取解密文件向量：{iv}")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        with open(out_filename, 'wb') as outfile:
            chunk = infile.read(chunksize)
            while True:
                next_chunk = infile.read(chunksize)
                if len(next_chunk) == 0:
                    if len(chunk) > 0:
                        # 去填充操作
                        chunk = unpad(cipher.decrypt(chunk), AES.block_size)
                        outfile.write(chunk)
                    break
                else:
                    outfile.write(cipher.decrypt(chunk))
                    chunk = next_chunk
    print("文件解密成功！")


if __name__ == '__main__':
    file_list = []
    if args.get_key:
        key = get_secret_key(args.key_length)
        print(f"获取16进制加密密钥：{binascii.hexlify(key).decode('utf-8')}")
        exit(0)
    if args.encrypto:
        my_key = args.key
        print(f"获取加密密钥：{my_key}")
        key = binascii.unhexlify(
            my_key.encode('utf-8'))  # This is your encryption key, make sure it's 16, 24 or 32 bytes long
        if args.file:
            file_list.append(args.file)
        if args.dir:
            file_list = get_files(args.dir) + file_list
        print(f"获取加密文件列表：{file_list}")
        for f in file_list:
            encrypt_file(key=key, in_filename=f, out_dir=args.out)
        exit(0)
    if args.decrypto:
        my_key = args.key
        print(f"获取解密密钥：{my_key}")
        key = binascii.unhexlify(my_key.encode('utf-8'))
        # print(key)
        if args.file:
            file_list.append(args.file)
        if args.dir:
            file_list = get_files(args.dir) + file_list
        print(f"获取解密文件列表：{file_list}")
        for f in file_list:
            decrypto_file(key=key, in_filename=f, out_dir=args.out)
        exit(0)
