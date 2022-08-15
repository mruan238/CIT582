from algosdk import mnemonic
from algosdk import account
from web3 import Web3


# generate account
mnemonic_secret = "Got perfect score"
sender_sk = mnemonic.to_private_key(mnemonic_secret)
sender_pk = mnemonic.to_public_key(mnemonic_secret)
print("sender_sk: ", sender_sk)
print("sender_pk: ", sender_pk)


# sender_sk:  JnU3uxlyHBK5Dut5KSzkkYu+FauQeG0U/iGLMmn4bt04XRixztR3qSmFsGpJL4BUeggwv35632TAUBmfXlJzMQ==
# sender_pk:  HBORRMOO2R32SKMFWBVESL4AKR5AQMF7PZ5N6ZGAKAMZ6XSSOMY2IRKSHU
# eth_sk:  b'Q\x15+E\xa1\xde\x84\xa7\xa4\x80/\xaf.\xf0%|\xf2\xc9\x93\xf9\xf1\xb7\xf2\x92\xaa\x01\x14\x8b\x17b\xf5\xac'
# eth_pk:  0xca76a112701A240BDb038d45839BA18c3015EA2c


w3 = Web3()
w3.eth.account.enable_unaudited_hdwallet_features()
acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
acct = w3.eth.account.from_mnemonic(mnemonic_secret)
eth_pk = acct._address
eth_sk = acct._private_key
print("eth_sk: ", eth_sk)
print("eth_pk: ", eth_pk)