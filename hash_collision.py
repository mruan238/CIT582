import hashlib
import os
import string
import random

def hash_collision(k):
    if not isinstance(k,int):
        print( "hash_collision expects an integer" )
        return( b'\x00',b'\x00' )
    if k < 0:
        print( "Specify a positive number of bits" )
        return( b'\x00',b'\x00' )
   
    #Collision finding code goes here
    x = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(k + random.randint(0,10))).encode('utf-8')
    y = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(k + random.randint(0,10))).encode('utf-8')
    while (bin(int(hashlib.sha256(x).hexdigest(), 16))[-k:]!= bin(int(hashlib.sha256(y).hexdigest(), 16))[-k:]):
        y = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(k + random.randint(0,10))).encode('utf-8')
    return ( x, y )