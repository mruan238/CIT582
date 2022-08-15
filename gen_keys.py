from algosdk import mnemonic
from algosdk import account
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound

w3 = Web3()
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret_eth = w3.eth.account.create_with_mnemonic()

with open('eth_mnemonic.txt', 'w') as f:
    f.write(mnemonic_secret_eth)

print(mnemonic_secret_eth)

algo_sk, algo_pk = account.generate_account()

mnemonic_secret_alg = mnemonic.from_private_key(algo_sk)

with open('alg_mnemonic.txt', 'w') as f:
    f.write(mnemonic_secret_alg)
