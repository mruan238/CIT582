from algosdk import mnemonic
from algosdk import account
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound

def get_keys_eth():
    eth_mnemonic = "beauty diagram educate skirt unfold sing chaos depend acoustic science engage rib"
    w3 = Web3()
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct = w3.eth.account.from_mnemonic(eth_mnemonic)
    eth_pk = acct._address
    eth_sk = acct._private_key.hex()
    return eth_sk,eth_pk

def get_keys_algo():
    mnemonic_secret = "soft quiz moral bread repeat embark shed steak chalk joy fetch pilot shift floor identify poverty index yard cannon divorce fatal angry mistake abandon voyage"
    sk = mnemonic.to_private_key(mnemonic_secret)
    pk = account.address_from_private_key(sk)
    return sk,pk


if __name__ == '__main__':
    sk,pk=get_keys_algo()
    print(sk)
    print(pk)