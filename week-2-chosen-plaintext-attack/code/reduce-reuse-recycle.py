from pwn import process, xor

"""
Idea:

We've AES with CTR mode.
So, it's a deterministic mode that uses a nonce value.
However, there is only one nonce that is used along all the encryptions.

In CTR mode, all blocks are encrypted independently and using nonce with an 
offset (index block).
So, if we use the same nonce, all the values used are the same in two different encryptions 
for i-th and j-th blocks if i = j.
With this in mind, suppose we've two blocks, then:
    c0 = F(k, IV) ^ m0 
    c1 = F(k, IV) ^ m1 
Therefore:
    m1 = c0 ^ c1 ^ m0

If m1 is the flag, we can encrypt some message (AAAA...AAAA) and then get the secret message 
xoring the message with its encryption and the flag ciphertext.
"""

r = process(["python3", "./reduce-reuse-recycle-statement.py"])
FLAG_SIZE = 16 * 3

m0 = b"A" * FLAG_SIZE
r.sendlineafter(b">> ", b"1")
r.sendlineafter(b"Message: ", m0)
c0 = bytes.fromhex(r.recvline().split(b": ")[1].decode())

r.sendlineafter(b">> ", b"2")
c1 = bytes.fromhex(r.recvline().split(b": ")[1].decode())

m1 = xor(c0, c1, m0)
flag = m1.split(b"}")[0] + b"}"
print(f"[+] Flag: {flag}")
