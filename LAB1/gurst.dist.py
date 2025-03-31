#!/usr/bin/env python3
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
import random
import base64
import zlib

msg0 = """MSG0"""
msg1 = """MSG1"""
msg2 = """MSG2"""
msg3 = """MSG3"""
msg4 = """MSG4"""

def sendmsg(m):
    zm = zlib.compress(m)
    mlen = len(zm)
    print('>>>', base64.b64encode(mlen.to_bytes(4, 'big') + zm).decode(), '<<<')

def recvmsg(prompt):
    sendmsg(prompt.encode())
    msg = input().strip()
    msg = base64.b64decode(msg.encode())
    mlen = int.from_bytes(msg[0:4], 'little')
    if len(msg)-4 != mlen: sendmsg(msg4.encode()); sys.exit(1)
    m = zlib.decompress(msg[4:]).decode()
    return m

ans, _ = list("0123456789"), sendmsg(msg0.encode())
random.shuffle(ans)
guess, ans, count = '', ''.join(ans[0:4]), 0
while guess != ans:
    guess = recvmsg(f"#{count+1} Enter your input (4 digits): ").strip()
    if len(set(guess)) != 4: sendmsg(msg1.encode()); continue
    a = sum([ 1 if guess[i] == ans[i]   else 0 for i in range(4) ])
    b = sum([ 1 if guess[i] in set(ans) else 0 for i in range(4) ]) - a
    sendmsg(a.to_bytes(4, 'big') + b'A' + b.to_bytes(4, 'big') + b'B')
    count += 1
    if guess == ans: sendmsg(msg1.encode()); break
    elif count < 10: sendmsg(msg2.encode())
    else: sendmsg(msg3.encode()); break # count >= 10