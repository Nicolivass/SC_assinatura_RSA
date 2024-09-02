import random
import math
import base64
import os
import sys
import hashlib
from hashlib import sha256
from pathlib import Path
from math import ceil

#teste de primalidade
def miller_rabin(n,k): 
    if n == 2 or n == 3:
        return True

    if n%2 == 0:
        return False

    r,s = 0, n-1
    while s%2 == 0:
        r+=1
        s//=2
    for _ in range(k):
        a = random.randrange(2, n-1)
        x = pow(a,s,n)
        if x == 1 or x == n-1:
            continue
        for _ in range(r-1):
            x = pow(x,2,n)
            if x == n - 1:
                break
        else:
            return False
    return True

#gera chave prima com teste de primalidade
def gera_primos():
    n = random.getrandbits(1024)
    if miller_rabin(n,40) == True:
        return n
    return gera_primos()

sys.setrecursionlimit(1500)

#gera p e q primos
while True:
    try:
        p = gera_primos() 
        q = gera_primos()
        break
    except: #RecursionError
        None

#encontra o inverso modular de a % m, que é o número x tal que a * x % m = 1.
def encontra_inverso_mod(a, m):
    if math.gcd(a, m) != 1: 
        return None

    u1, u2, u3 = 1, 0, a 
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

n = p*q 

fn = (p-1)*(q-1) 

e=0

#encontra um e, tal que o MDC (máximo divisor comum) de f(n) & e = 1, onde 1 < e < f(n).
while (math.gcd(fn, e) != 1): 
    e = random.randrange(2, fn)

#encontra um d tal que ed mod mod f(n) = 1
d = encontra_inverso_mod(e, fn) 

chave_privada = (d, n) 
chave_publica = (e, n)

print("p com teste de primalidade (Miller-Rabin) =", p)
print("q  com teste de primalidade (Miller-Rabin) =", q)


with open(Path(__file__).absolute().parent / "mensagem.txt", "rb") as file: # Leitura do arquivo "mensagem.txt"
    conteudo = file.read()

conteudo = base64.encodebytes(conteudo)

def xor_bloco(mensagem, mask):
    result = []
    for a,b in zip(mensagem, mask):
        result.append(a^b)

    resultado_lista_bytes = bytearray(result)
    
    return resultado_lista_bytes

#gera semente aleatória
seed = random.getrandbits(2**(n - 1))

#função usada para a cifração RSA
def codifica_oaep_rsa(message, n, k):
    #verifica o tamanho
    message_length = len(message)
    if message_length > n - k:
        raise ValueError("Menssagem muito longa para tamanho da chave")

    #gera hash da semente
    hash_seed = sha256(seed.to_bytes((seed.bit_length() + 7) // 8, byteorder='big')).digest()

    #XOR da mensagem com a semente
    padded_message = message + b'\x00' * (n - message_length - k)
    padded_message = bytearray(padded_message)
    for i in range(len(padded_message)):
        padded_message[i] ^= hash_seed[i % len(hash_seed)]
        
    return pow(int.from_bytes(padded_message, byteorder='big'), e, n)

#função usada para a decifração RSA
def cedodifica_oap_rsa(ciphertext, d, n, k):
    # Decifra a mensagem
    padded_message = pow(ciphertext, d, n)
    padded_message = padded_message.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    # Desfaz o padding
    hash_seed = sha256(seed.to_bytes((seed.bit_length() + 7) // 8, byteorder='big')).digest()
    original_message = bytearray(padded_message)
    for i in range(len(original_message)):
        original_message[i] ^= hash_seed[i % len(hash_seed)]

    return original_message.rstrip(b'\x00')

def sha3_224(m):
    sha3 = hashlib.sha3_224()
    sha3.update(m)
    return sha3.digest()

resultado_sha = sha3_224(conteudo)

mensagem = base64.encodebytes(resultado_sha)

def mgf1(seed, mlen):
    t = b''
    hlen = 28

    for c in range(0, ceil(mlen / hlen)):
        c_ = c.to_bytes(4, byteorder='big')
        t += sha3_224(seed + c_)

    return t[:mlen]

#função usada para a cifração do hash
def codifica_oaep(m, k, label = b'', mgf1 = mgf1) -> bytes:
    mlen = len(m)
    lhash = sha3_224(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = xor_bloco(db, db_mask)
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = xor_bloco(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db

def cifra(mensagem, chave_publica):
    e, n = chave_publica
    return pow(mensagem, e, n)

def cifra_raw(mensagem, chave_publica):
    k = chave_publica[1].bit_length() // 8
    c = cifra(
        int.from_bytes(mensagem, byteorder='big'),
        chave_publica
    )
    return c.to_bytes(length=k+1, byteorder='big')

hash_length = 28 

k = chave_publica[1].bit_length() // 8 #calcula o número de octetos na chave.

cifrado_oaep = codifica_oaep(mensagem, k) #cifração OAEP.
c = cifra_raw(cifrado_oaep, chave_publica)

#função usada para a decifração do hash
def oaep_decifra(c: bytes, k: int, label: bytes = b'', sha3_224 = sha3_224) -> bytes:
    clen = len(c)
    lhash = sha3_224(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = xor_bloco(masked_seed, seed_mask)
    db_mask = mgf1(seed, k - hlen - 1)
    db = xor_bloco(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m

def decifra(c: int, chave_privada):
    d, n = chave_privada
    return pow(c, d, n)

def decifra_raw(mensagem, chave_privada):
    k = chave_privada[1].bit_length() // 8
    m = decifra(int.from_bytes(mensagem, byteorder='big'), chave_privada)
    return m.to_bytes(k, byteorder='big')


k = chave_privada[1].bit_length() // 8
hlen = 28
oaep_decifrado = oaep_decifra(decifra_raw(c, chave_privada), k)


print('SHA3_224 =', base64.encodebytes(resultado_sha))
print("Hash da mensagem cifrada =", cifrado_oaep)
print("Hash da mensagem cifrada formatada =", base64.encodebytes(cifrado_oaep))
print("Assinatura decifrada =", oaep_decifrado)
print("Verificação =")
print("   ", base64.encodebytes(resultado_sha),"= ",oaep_decifrado,"?")
if base64.encodebytes(resultado_sha) == oaep_decifrado:
    print("OK")
else:
    print("NOT OK")


