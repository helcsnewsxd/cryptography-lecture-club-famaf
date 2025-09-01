import requests
import string
from concurrent.futures import ThreadPoolExecutor
from itertools import chain

"""
Idea:

In ECB mode, each block is encrypted separately and independently.
So, if two blocks are the same, their encryption is also the same because ECB is deterministic.
Therefore, suppose we want to know the first byte of the flag.
Since size block is 16, if we send "AAAAAAAAAAAAAAAA", the encryption of the second block 
ct[16:] will have the first 16 bytes of flag.
The idea is to bruteforce the last byte sending 15 As and a char guess c.
If we obtain a block with its encryption equal as the first 16 bytes of flag, then char guess 
is the correct one.

We can do it recursively sending less As and concatenating with the current flag known and the 
actual char guess.
Since 16 isn't the flag size (it's 32 or less), the final idea is to do the same as before but 
with LIMIT = 32.
"""

URL = "https://aes.cryptohack.org/ecb_oracle"
s = requests.session()
SEGMENT = 25
CHARS = [
    string.printable[i : i + SEGMENT] for i in range(0, len(string.printable), SEGMENT)
]


def encrypt(plaintext):
    r = s.get(f"{URL}/encrypt/{plaintext.hex()}/", timeout=10)
    ct = bytes.fromhex(r.json()["ciphertext"])
    return ct


LIMIT = len(encrypt(b"A"))


def processing(plaintext):
    ct_blocks = encrypt(plaintext)
    ct_list = [ct_blocks[i : i + LIMIT] for i in range(0, len(ct_blocks), LIMIT)]
    return ct_list[:-1]


flag = b""
for k in range(LIMIT):
    cntA = LIMIT - k - 1
    target = encrypt(b"A" * cntA)[:LIMIT]
    try_blocks = [
        b"".join([b"A" * cntA + flag + c.encode() for c in CHARS[i]])
        for i in range(len(CHARS))
    ]

    with ThreadPoolExecutor() as executor:
        guess_blocks = list(executor.map(processing, try_blocks))
        guess_blocks = list(chain(*guess_blocks))

    find_guess = False
    for guess, c in zip(guess_blocks, string.printable):
        if guess == target:
            flag += c.encode()
            find_guess = True
            print(f"[+] Found new character! -> {c.encode()}")
            break
    if not find_guess:
        break

print(f"[+] Flag: {flag}")
