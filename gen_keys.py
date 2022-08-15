from algosdk import mnemonic
from algosdk import account
from web3 import Web3


# generate account
mnemonic_secret = "exclude shop before cheap forward gadget loop route skin trash absent feed alien cluster federal regular mix mixed result soon mixed radio cage abstract try"
sender_sk = mnemonic.to_private_key(mnemonic_secret)
sender_pk = mnemonic.to_public_key(mnemonic_secret)
print("sender_sk: ", sender_sk)
print("sender_pk: ", sender_pk)


w3 = Web3()
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
acct = w3.eth.account.from_mnemonic(mnemonic_secret)
eth_pk = acct._address
eth_sk = acct._private_key
print("eth_sk: ", eth_sk)
print("eth_pk: ", eth_pk)