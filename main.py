import random
import struct
import sys

from Crypto.Util.number import *
import codecs
import Crypto
from Crypto import Random
from Crypto.Util.py3compat import b


def encryption(plaintext, n):

    plaintext = padding(plaintext)
    return plaintext ** 2 % n



def padding(plaintext):
    binary_str = bin(plaintext)  # convert to a bit string
    output = binary_str + binary_str[-16:]  # pad the last 16 bits to the end
    return int(output, 2)  # convert back to integer


def decryption(a, p, q):
    n = p * q
    r, s = 0, 0
    # find sqrt
    # for p
    if p % 4 == 3:
        r = sqrt_p_3_mod_4(a, p)
    elif p % 8 == 5:
        r = sqrt_p_5_mod_8(a, p)
    # for q
    if q % 4 == 3:
        s = sqrt_p_3_mod_4(a, q)
    elif q % 8 == 5:
        s = sqrt_p_5_mod_8(a, q)

    gcd, c, d = egcd(p, q)
    x = (r * d * q + s * c * p) % n
    y = (r * d * q - s * c * p) % n
    lst = [x, n - x, y, n - y]
    print("\nCipher text "+str(lst))
    plaintext = choose(lst)

    string = bin(plaintext)
    string = string[:-16]
    plaintext = int(string, 2)

    return plaintext



def choose(lst):
    for i in lst:
        binary = bin(i)

        append = binary[-16:]  # take the last 16 bits
        binary = binary[:-16]  # remove the last 16 bits

        if append == binary[-16:]:
            return i
    return

def bytes_to_long(s):
    """bytes_to_long(string) : long
    Convert a byte string to a long integer.

    This is (essentially) the inverse of long_to_bytes().
    """
    acc = 0
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b('\000') * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

# Find SQROOT in Zp where p = 3 mod 4
def sqrt_p_3_mod_4(a, p):
    r = pow(a, (p + 1) // 4, p)
    return r


# Find SQROOT in Zp where p = 5 mod 8
def sqrt_p_5_mod_8(a, p):
    d = pow(a, (p - 1) // 4, p)
    r = 0
    if d == 1:
        r = pow(a, (p + 3) // 8, p)
    elif d == p - 1:
        r = 2 * a * pow(4 * a, (p - 5) // 8, p) % p

    return r


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, y, x = egcd(b % a, a)
        return gcd, x - (b // a) * y, y


bits = 60

msg = input("\nВведите исходный текст: ")
print()

if (len(sys.argv) > 1):
    msg = str(sys.argv[1])
if (len(sys.argv) > 2):
    bits = int(sys.argv[2])

while True:
    #p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    p=931574284005375799
    if ((p % 4) == 3): break

while True:
    #q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q=690096964083142883
    if ((p % 4) == 3): break

n = p * q
#input()
print("=== CryptoLab1--SavchenkoMV ===")
print(("Plaintext=%s") % msg)
print(("\n=== Private Keys (%d bit большие простые числа) ===") % bits)
print(("p=%d, q=%d") % (p, q))

print("\n=== Public key ===")
print("n=p*q=%d" % n)

plaintext = bytes_to_long(msg.encode('utf-8'))

ciphertext = encryption(plaintext, n)
#print("\nCipher:", ciphertext)

plaintext = decryption(ciphertext, p, q)

st = format(plaintext, 'x')
print("\nРасшифрование plaintext: ")
print()
print("Исходный открытый текст: "+bytes.fromhex(st).decode())