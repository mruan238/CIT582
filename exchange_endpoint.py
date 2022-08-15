from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import load_only
from datetime import datetime
import math
import sys
import traceback
import send_tokens
from algosdk import mnemonic
from algosdk import account
from web3 import Web3

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth

from models import Base, Order, TX, Log

engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

eth_sk, eth_pk = 0, 0
algo_sk, algo_pk = 0, 0

""" Pre-defined methods (do not need to change) """


@app.before_request
def create_session():
    g.session = scoped_session(DBSession)


@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


def connect_to_blockchains():
    try:
        # If g.acl has not been defined yet, then trying to query it fails
        acl_flag = False
        g.acl
    except AttributeError as ae:
        acl_flag = True

    try:
        if acl_flag or not g.acl.status():
            # Define Algorand client for the application
            g.acl = connect_to_algo()
    except Exception as e:
        print("Trying to connect to algorand client again")
        print(traceback.format_exc())
        g.acl = connect_to_algo()

    try:
        icl_flag = False
        g.icl
    except AttributeError as ae:
        icl_flag = True

    try:
        if icl_flag or not g.icl.health():
            # Define the index client
            g.icl = connect_to_algo(connection_type='indexer')
    except Exception as e:
        print("Trying to connect to algorand indexer client again")
        print(traceback.format_exc())
        g.icl = connect_to_algo(connection_type='indexer')

    try:
        w3_flag = False
        g.w3
    except AttributeError as ae:
        w3_flag = True

    try:
        if w3_flag or not g.w3.isConnected():
            g.w3 = connect_to_eth()
    except Exception as e:
        print("Trying to connect to web3 again")
        print(traceback.format_exc())
        g.w3 = connect_to_eth()


""" End of pre-defined methods """

""" Helper Methods (skeleton code for you to implement) """


def log_message(message_dict):
    msg = json.dumps(message_dict)

    # TODO: Add message to the Log table
    log_obj = Log(logtime=datetime.now(), message=msg)
    g.session.add(log_obj)
    g.session.commit()
    return


def get_algo_keys():
    # TODO: Generate or read (using the mnemonic secret)
    # the algorand public/private keys
    mnemonic_secret = "purse reason lab neglect trial prosper play season jacket sea earth decide title acid poet safe comic hood travel trend midnight giggle anchor abandon regret"
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    return algo_sk, algo_pk


def get_eth_keys(filename="eth_mnemonic.txt"):
    w3 = Web3()

    # TODO: Generate or read (using the mnemonic secret)
    # the ethereum public/private keys
    w3.eth.account.enable_unaudited_hdwallet_features()
    acct, mnemonic_secret = w3.eth.account.create_with_mnemonic()
    acct = w3.eth.account.from_mnemonic(mnemonic_secret)
    eth_pk = acct._address
    eth_sk = acct._private_key
    return eth_sk, eth_pk


def fill_order(order, txes=[]):
    # TODO:
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    order_obj = Order(sender_pk=order['sender_pk'], receiver_pk=order['receiver_pk'],
                      buy_currency=order['buy_currency'], sell_currency=order['sell_currency'],
                      buy_amount=order['buy_amount'], sell_amount=order['sell_amount'],
                      creator_id=order.get('creator_id'))

    result = g.session.query(Order).filter(Order.filled == None, Order.buy_currency == order['sell_currency'],
                                           Order.sell_currency == order['buy_currency'],
                                           Order.sell_amount / Order.buy_amount >= order['buy_amount'] / order[
                                               'sell_amount']).first()
    if result == None:
        g.session.add(order_obj)
        g.session.commit()
        return

    order_obj.filled = datetime.now()
    order_obj.counterparty_id = result.id

    g.session.add(order_obj)
    g.session.commit()

    result.filled = datetime.now()
    result.counterparty_id = order_obj.id
    g.session.commit()

    tx_dict = {'order_id': order_obj.id, 'platform': order["sell_currency"], 'receiver_pk': order['receiver_pk'],
               'order': result, 'tx_amount': order["sell_amount"]}
    txes.append(tx_dict)


    if order_obj.buy_amount > result.sell_amount:
        new_buy_amount = order_obj.buy_amount - result.sell_amount
        new_sell_amount = new_buy_amount * order_obj.sell_amount / order_obj.buy_amount

        new_order = {'buy_currency': order_obj.buy_currency, 'sell_currency': order_obj.sell_currency,
                     'buy_amount': new_buy_amount, 'sell_amount': new_sell_amount, 'sender_pk': order_obj.sender_pk,
                     'receiver_pk': order_obj.receiver_pk, 'creator_id': order_obj.id}
        txes.append(fill_order(new_order))

    if order_obj.buy_amount < result.sell_amount:
        new_sell_amount = result.sell_amount - order_obj.buy_amount
        new_buy_amount = new_sell_amount * result.buy_amount / result.sell_amount

        new_order = {'buy_currency': result.buy_currency, 'sell_currency': result.sell_currency,
                     'buy_amount': new_buy_amount, 'sell_amount': new_sell_amount, 'sender_pk': result.sender_pk,
                     'receiver_pk': result.receiver_pk, 'creator_id': result.id}
        txes.append(fill_order(new_order))

    return txes


def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print(f"Trying to execute {len(txes)} transactions")
    print(f"IDs = {[tx['order_id'] for tx in txes]}")
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()

    if not all(tx['platform'] in ["Algorand", "Ethereum"] for tx in txes):
        print("Error: execute_txes got an invalid platform!")
        print(tx['platform'] for tx in txes)

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand"]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum"]

    w3 = Web3()

    # TODO:
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    algo_tx_ids = send_tokens_algo(g.acl, algo_sk, algo_txes)
    eth_tx_ids = send_tokens_eth(w3, eth_sk, eth_txes)

    i = 0
    for tx in algo_txes:
        tx_obj = TX(order_id = tx.order_id, tx_id = algo_tx_ids[i])
        print(tx_obj)
        g.session.add(tx_obj)
        g.session.commit()
        i += 1

    j = 0
    for tx in eth_txes:
        tx_obj = TX(order_id = tx.order_id, tx_id = eth_tx_ids[j])
        print(tx_obj)
        g.session.add(tx_obj)
        g.session.commit()
        j += 1
    pass


""" End of Helper methods"""


@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        payload = content.get('payload')
        platform = content.get('platform')
        if platform == None:
            platform = payload.get('platform')

        if platform == "Ethereum":
            # Your code here
            eth_sk, eth_pk = get_eth_keys()
            # print(eth_pk, jsonify(eth_pk))
            return jsonify(eth_pk)
        if platform == "Algorand":
            # Your code here
            algo_sk, algo_pk = get_algo_keys()
            return jsonify(algo_pk)


@app.route('/trade', methods=['POST'])
def trade():
    print("In trade", file=sys.stderr)
    connect_to_blockchains()
    w3 = Web3()
    server_pk = address()
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = ["buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = ["sig", "payload"]
        error = False
        for field in fields:
            if not field in content.keys():
                print(f"{field} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print(f"{column} not received by Trade")
                error = True
        if error:
            print(json.dumps(content))
            return jsonify(False)

        # Your code here

        # 1. Check the signature

        # 2. Add the order to the table

        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)

        # 3b. Fill the order (as in Exchange Server II) if the order is valid

        # 4. Execute the transactions

        # If all goes well, return jsonify(True). else return jsonify(False)
        payload = content.get('payload')
        platform = content.get('platform')
        if platform == None:
            platform = payload.get('platform')
        sig = content.get('sig')
        pk = payload.get('sender_pk')
        id = payload.get('tx_id')
        buy_currency = payload.get('buy_currency')
        sell_currency = payload.get('sell_currency')
        buy_amount = payload.get('buy_amount')
        sell_amount = payload.get('sell_amount')
        sig_result = False

        if platform == 'Ethereum':
            msg = json.dumps(payload)
            encoded_msg = eth_account.messages.encode_defunct(text=msg)
            if eth_account.Account.recover_message(encoded_msg, signature=sig) == pk:
                sig_result = True

        if platform == 'Algorand':
            msg = json.dumps(payload)
            if algosdk.util.verify_bytes(msg.encode('utf-8'), sig, pk):
                sig_result = True

        # print(result)
        validity = False
        # print(platform)
        if platform == 'Ethereum':
            tx = w3.eth.get_transaction(id)
            gas = tx.get('result').get('value')
            sender = tx.get('result').get('from')
            receiver = tx.get('result').get('to')
            if gas == sell_amount and sender == pk and receiver == server_pk:
                validity = True

        if platform == 'Algorand':
            tx = g.icl.search_transactions(txid=id)
            amount = tx.get('transactions')[0].get('payment-transaction').get('amount')
            sender = tx.get('transactions')[0].get('sender')
            receiver = tx.get('transactions')[0].get('payment-transaction').get('receiver')
            if amount == sell_amount and sender == pk and receiver == server_pk:
                validity = True

        # TODO: Add the order to the database

        if sig_result and validity:
            # TODO: Fill the order
            order = {}
            order['buy_currency'] = payload.get('buy_currency')
            order['sell_currency'] = payload.get('sell_currency')
            order['buy_amount'] = payload.get('buy_amount')
            order['sell_amount'] = payload.get('sell_amount')
            order['sender_pk'] = payload.get('sender_pk')
            order['receiver_pk'] = payload.get('receiver_pk')
            txes = fill_order(order)
            execute_txes(txes)
        else:
            log_message(payload)
            return jsonify(False)
        return jsonify(True)


@app.route('/order_book')
def order_book():
    temp_list = []
    for row in g.session.query(Order).all():
        temp = {'sender_pk': row.sender_pk, 'receiver_pk': row.receiver_pk, 'buy_currency': row.buy_currency,
                'sell_currency': row.sell_currency, 'buy_amount': row.buy_amount, 'sell_amount': row.sell_amount,
                'tx_id': row.tx_id}
        result = g.session.query(TX).filter(TX.order_id == row.id).first()
        temp["tx_id"] = result.tx_id

        print(temp)
        temp_list.append(temp)

    result = {'data': temp_list}
    print(result)
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')