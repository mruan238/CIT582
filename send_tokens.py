from algosdk import account
from algosdk import mnemonic
from algosdk.mnemonic import from_private_key
from algosdk.future import transaction
from algosdk.v2client import algod
from algosdk.v2client import indexer

def connect_to_algo(connection_type=''):
    # Connect to Algorand node maintained by PureStake
    algod_token = "B3SU4KcVKi94Jap2VXkK83xx38bsv95K5UZm2lab"
    headers = {"X-API-Key": algod_token, }

    if connection_type == "indexer":
        # TODO: return an instance of the v2client indexer. This is used for checking payments for tx_id's
        algod_address = "https://testnet-algorand.api.purestake.io/idx2"
        algodclient = indexer.IndexerClient(
            algod_token, algod_address, headers)
    else:
        # TODO: return an instance of the client for sending transactions
        algod_address = "https://testnet-algorand.api.purestake.io/ps2"
        algodclient = algod.AlgodClient(algod_token, algod_address, headers)

    return algodclient


def send_tokens_algo(acl, sender_sk, txes):
    # TODO: You might want to adjust the first/last valid rounds in the suggested_params
    #       See guide for details

    # TODO: For each transaction, do the following:
    #       - Create the Payment transaction 
    #       - Sign the transaction
    
    # TODO: Return a list of transaction id's
    params = acl.suggested_params()
    sender_pk = account.address_from_private_key(sender_sk)
    receiver_pk = txes[0]['receiver_pk']
    tx_amount = txes[0]['send_amount']

    unsigned_tx = transaction.PaymentTxn(sender_pk, params, receiver_pk, tx_amount)

    signed_tx = unsigned_tx.sign(sender_sk)

    sent_tx = acl.send_transaction(signed_tx)
    wait_for_confirmation_algo(acl, sent_tx)

    return sent_tx


# Function from Algorand Inc.


def wait_for_confirmation_algo(client, txid):
    """
    Utility function to wait until the transaction is
    confirmed before proceeding.
    """
    last_round = client.status().get('last-round')
    txinfo = client.pending_transaction_info(txid)
    while not (txinfo.get('confirmed-round') and txinfo.get('confirmed-round') > 0):
        print("Waiting for algo confirmation")
        last_round += 1
        client.status_after_block(last_round)
        txinfo = client.pending_transaction_info(txid)
    print("Transaction {} confirmed in round {}.".format(
        txid, txinfo.get('confirmed-round')))
    return txinfo

##################################

from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound
import json
import progressbar

def connect_to_eth():
    IP_ADDR = '3.23.118.2'  # Private Ethereum
    PORT = '8545'

    w3 = Web3(Web3.HTTPProvider('http://' + IP_ADDR + ':' + PORT))
    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    # Required to work on a PoA chain (like our private network)
    w3.eth.account.enable_unaudited_hdwallet_features()
    if w3.isConnected():
        return w3
    else:
        print("Failed to connect to Eth")
        return None


def wait_for_confirmation_eth(w3, tx_hash):
    print("Waiting for confirmation")
    widgets = [progressbar.BouncingBar(
        marker=progressbar.RotatingMarker(), fill_left=False)]
    i = 0
    with progressbar.ProgressBar(widgets=widgets, term_width=1) as progress:
        while True:
            i += 1
            progress.update(i)
            try:
                receipt = w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                continue
            break
    return receipt


####################
def send_tokens_eth(w3, sender_sk, txes):

    sender_account = w3.eth.account.privateKeyToAccount(sender_sk)
    sender_pk = sender_account._address
    # TODO: For each of the txes, sign and send them to the testnet
    # Make sure you track the nonce -locally-
    starting_nonce = w3.eth.get_transaction_count(sender_pk, 'pending')
    receiver_public_ley = txes[0]['receiver_pk']
    tx_amount = txes[0]['send_amount']

    tx_dict = {
        'nonce': starting_nonce,
        'gasPrice': w3.eth.gas_price,
        'gas': w3.eth.estimate_gas({'from': sender_pk, 'to': receiver_public_ley, 'data': b'', 'amount': tx_amount}),
        'to': receiver_public_ley,
        'value': tx_amount,
        'data': b''}

    signed_tx = w3.eth.account.sign_transaction(tx_dict, sender_sk)
    tx_id = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    wait_for_confirmation_eth(w3, tx_id)

    return 