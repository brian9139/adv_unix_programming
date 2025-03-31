#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import base64
import zlib
import itertools
import re
from pwn import *
from solpow import solve_pow

def sendmsg(m):
    """
    發送壓縮與 Base64 編碼的訊息。
    這裡使用 little-endian 編碼長度，因為 server 解析 client 訊息時用 little-endian。
    """
    zm = zlib.compress(m.encode())
    mlen = len(zm)
    encoded = base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode()
    r.sendline(encoded.encode())

def decode_message(msg):
    """
    解碼來自 server 的訊息。
    Server 發送時使用 big-endian 編碼長度，
    但回傳的資料可能是純文字提示或是 binary 回饋。
    """
    # 移除標記 >>> 與 <<<
    msg = msg.decode().strip().replace(">>>", "").replace("<<<", "").strip()
    try:
        data = base64.b64decode(msg)
        # 前 4 bytes 是長度，使用 big-endian 解析
        length = int.from_bytes(data[:4], 'big')
        actual_data = data[4:]
        if len(actual_data) != length:
            log.failure(f"Invalid message length: expected {length}, got {len(actual_data)}")
            sys.exit(1)
        decompressed = zlib.decompress(actual_data)
    except Exception as e:
        log.failure(f"Decoding error: {e}, data={msg}")
        sys.exit(1)

    # 如果解壓後的資料中含有 null bytes，就認定它是 binary 回饋
    if b'\x00' in decompressed[:4]:
        # 假設 binary 回饋格式： a.to_bytes(4, 'big') + b'A' + b.to_bytes(4, 'big') + b'B'
        if len(decompressed) == 10:
            a = int.from_bytes(decompressed[0:4], 'big')
            b_val = int.from_bytes(decompressed[5:9], 'big')
        elif len(decompressed) == 6:
            a = int.from_bytes(decompressed[0:2], 'big')
            b_val = int.from_bytes(decompressed[3:5], 'big')
        else:
            log.failure(f"Unexpected feedback format with length {len(decompressed)}")
            sys.exit(1)
        return f"{a}A{b_val}B"
    else:
        # 否則認定為純文字訊息
        return decompressed.decode().strip()

def recv_message():
    """
    從 server 接收訊息，並提取有效的遊戲資訊。
    當訊息包含 "Enter your input" 時，回傳 "INPUT"，
    否則若訊息符合 nA nB 格式，回傳該回饋字串。
    """
    while True:
        try:
            line = r.recvline().strip()
            if line.startswith(b'>>>') and line.endswith(b'<<<'):
                message = decode_message(line)
                log.info(f"[DEBUG] Decoded message: \n{message}")
                if "Enter your input" in message:
                    return "INPUT"
                m = re.search(r"(\d+)A(\d+)B", message)
                if m:
                    return m.group(0)
            else:
                continue
        except EOFError:
            log.failure("Connection closed by server .")
            sys.exit(1)

def score(guess, actual):
    """ 計算 1A2B 分數 """
    a = sum(1 for i in range(4) if guess[i] == actual[i])
    b = sum(1 for i in range(4) if guess[i] in actual) - a
    return (a, b)

def play_game():
    """
    1A2B 遊戲邏輯：
    - 利用 itertools.permutations 產生所有可能的 4 位數候選答案
    - 根據每次猜測的回饋 (例如 "0A0B") 來篩選候選答案
    - 若猜中（4A0B），則結束遊戲
    """
    digits = "0123456789"
    candidates = ["".join(p) for p in itertools.permutations(digits, 4)]
    attempt = 0

    # 等待 server 發送初始提示訊息
    while True:
        response = recv_message()
        if response == "INPUT":
            break

    while attempt < 10:
        if not candidates:
            log.failure("No candidates left, something is wrong with feedback parsing.")
            sys.exit(1)

        guess = candidates[0]
        log.info(f"[*] Attempt {attempt + 1}: Guessing {guess}")
        sendmsg(guess)

        # 等待並取得回饋訊息（非提示訊息）
        feedback = None
        while True:
            response = recv_message()
            if response != "INPUT":
                feedback = response
                break

        log.info(f"[DEBUG] Feedback: {feedback}")
        m = re.search(r"(\d+)A(\d+)B", feedback)
        if not m:
            log.failure(f"Invalid feedback format: {feedback}")
            sys.exit(1)
        a_count, b_count = int(m.group(1)), int(m.group(2))
        if a_count == 4:
            log.success(f"Correct answer: {guess}")
            
            # **新增這段：確保讀取完整的 server 回應**
            while True:
                extra_msg = recv_message()
                if "INPUT" in extra_msg:
                    break  # 停止讀取，準備進入 interactive mode
                log.info(f"[DEBUG] Extra server message: {extra_msg}")

            return  # 完成遊戲後回到主函式

        # 根據回饋更新候選答案
        candidates = [c for c in candidates if score(guess, c) == (a_count, b_count)]
        attempt += 1

        # 等待下一次的輸入提示訊息
        while True:
            response = recv_message()
            if response == "INPUT":
                break

    log.failure("Failed to guess the correct number")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        r = process('./guess.dist.py', shell=False)

    log.info("Starting the game...")
    play_game()
    r.interactive()
