from algosdk import mnemonic
from algosdk import account
from web3 import Web3


# generate account
mnemonic_secret = "spray produce monitor fun pen census cupboard ten ski year describe wall"
sender_sk = mnemonic.to_private_key(mnemonic_secret)
sender_pk = mnemonic.to_public_key(mnemonic_secret)
print("sender_sk: ", sender_sk)
print("sender_pk: ", sender_pk)

