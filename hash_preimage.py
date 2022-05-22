import hashlib
import os
import string
import random

def hash_preimage(target_string):
    if not all( [x in '01' for x in target_string ] ):
        print( "Input should be a string of bits" )
        return 
    k = len(target_string)
    nonce = '00'
    while (bin(int(hashlib.sha256(nonce.encode('utf-8')).hexdigest(), 16))[-k:] != target_string):
        nonce = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(k + random.randint(0,10)))
    return( nonce )
