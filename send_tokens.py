#!/usr/bin/python3

from algosdk.v2client import algod
from algosdk import mnemonic
from algosdk import transaction
from algosdk import account, encoding

#Connect to Algorand node maintained by PureStake
#Connect to Algorand node maintained by PureStake
algod_address = "https://testnet-algorand.api.purestake.io/ps2"
algod_token = "B3SU4KcVKi94Jap2VXkK83xx38bsv95K5UZm2lab"
#algod_token = 'IwMysN3FSZ8zGVaQnoUIJ9RXolbQ5nRY62JRqF2H'
headers = {
   "X-API-Key": algod_token,
}

acl = algod.AlgodClient(algod_token, algod_address, headers)
min_balance = 100000 #https://developer.algorand.org/docs/features/accounts/#minimum-balance

private_key="/UaqxhwxbyWTZsX7qBJHwT4lo3PGZa6m/eD8IfxTkPa3Zt0v5uwxL4Y1YBhi/6C9+wfZ4oAcRuj6GrYL2SZDNg=="
address="W5TN2L7G5QYS7BRVMAMGF75AXX5QPWPCQAOEN2H2DK3AXWJGIM3NFNL4DY"


def send_tokens( receiver_pk, tx_amount ):
    params = acl.suggested_params()
    gen_hash = params.gh
    first_valid_round = params.first
    tx_fee = params.min_fee
    last_valid_round = params.last

    #Your code here
    unsigned_txn = transaction.PaymentTxn(address, tx_fee, first_valid_round, last_valid_round, gen_hash, receiver_pk, tx_amount, close_remainder_to=None, note=None, gen=None, flat_fee=False, lease=None, rekey_to=None)
    # sign transaction
    signed_txn = unsigned_txn.sign(private_key)
    # send transaction
    txid = acl.send_transaction(signed_txn)
    # print("Send transaction with txID: {}".format(txid))
    sender_pk=address
    
    return sender_pk, txid

# Function from Algorand Inc.
def wait_for_confirmation(client, txid):
    """
    Utility function to wait until the transaction is
    confirmed before proceeding.
    """
    last_round = client.status().get('last-round')
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
        print("Waiting for confirmation")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    print("Transaction {} confirmed in round {}.".format(txid, txinfo.get('confirmed-round')))
    return txinfo