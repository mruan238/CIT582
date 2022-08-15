from algosdk import mnemonic
from algosdk import account
from web3 import Web3


# generate account
mnemonic_secret = 'purse reason lab neglect trial prosper play season jacket sea earth decide title acid poet safe comic hood travel trend midnight giggle anchor abandon regret'
sender_sk = mnemonic.to_private_key(mnemonic_secret)
sender_pk = mnemonic.to_public_key(mnemonic_secret)
print("sender_sk: ", sender_sk)
print("sender_pk: ", sender_pk)
