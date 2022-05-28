import random
from params import p
from params import g

q = (p-1)/2
def keygen():
    if q:
        a =  random.randint(1,q)
    else:
        a = random.randint(1,p)
    sk = a
    pk = pow(g,a,p)
    return pk,sk

def encrypt(pk,m):
    r = random.randint(1, q)
    c1 = pow(g,r,p)
    c2 = (pow(pk,r,p) * m % p) % p
    return [c1,c2]

def decrypt(sk,c):
    m1 = pow(c[1], 1, p)
    m2 = pow(c[0], -sk, p)
    m = m1*m2 % p
    return m