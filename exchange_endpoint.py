from flask import Flask, request, g
from flask_restful import Resource, Api
from sqlalchemy import create_engine
from flask import jsonify
import json
import eth_account
import algosdk
from sqlalchemy.orm import sessionmaker
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

# TODO: make sure you implement connect_to_algo, send_tokens_algo, and send_tokens_eth
from send_tokens import connect_to_algo, connect_to_eth, send_tokens_algo, send_tokens_eth, Web3
from algosdk import account, mnemonic
from web3 import Web3

from models import Base, Order, TX, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

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

def check_sig(payload,sig):
    payload_str = json.dumps(payload)
    sender_pk = payload.get('sender_pk')
    platform = payload.get('platform')
    
    if platform == 'Algorand':
        result = algosdk.util.verify_bytes(payload_str.encode('utf-8'),sig, sender_pk)
    elif platform == 'Ethereum':
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload_str)
        result = eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == sender_pk
    return result

def log_message(d):
    g.session.add(Log(message=json.dumps(d)))
    g.session.commit()


def match_order(new_order, old_order):
    cond1 = new_order.filled == None
    cond2 = new_order.sell_currency == old_order.buy_currency
    cond3 = new_order.buy_currency == old_order.sell_currency
    cond4 = ((new_order.sell_amount * old_order.sell_amount) >= (new_order.buy_amount * old_order.buy_amount))
    return (cond1 & cond2 & cond3 & cond4) 

def fill_order(order,txes=[]):
    buy_currency = order['buy_currency']
    sell_currency = order['sell_currency']
    buy_amount = order['buy_amount']
    sell_amount = order['sell_amount']
    sender_pk = order['sender_pk']
    receiver_pk = order['receiver_pk']
    tx_id = order['tx_id']
    
    if order.get('creator_id') == None:
        new_order = Order(buy_currency = buy_currency,
                      sell_currency = sell_currency,
                      buy_amount = buy_amount,
                      sell_amount = sell_amount,
                      sender_pk = sender_pk,
                      receiver_pk = receiver_pk,
                      tx_id = tx_id)
    else: 
        new_order = Order(buy_currency = buy_currency,
                      sell_currency = sell_currency,
                      buy_amount = buy_amount,
                      sell_amount = sell_amount,
                      sender_pk = sender_pk,
                      receiver_pk = receiver_pk,
                      tx_id = tx_id,
                      creator_id = order.get('creator_id'))
        
    g.session.add(new_order)
    g.session.commit()
    
    unfilled_orders = g.session.query(Order).filter(Order.filled == None).all()
    
    for old_order in unfilled_orders:
        if match_order(new_order, old_order):
            
            old_order.filled = datetime.now()
            new_order.filled = datetime.now()
            old_order.counterparty_id = new_order.id
            new_order.counterparty_id = old_order.id
            g.session.commit()
            
            if new_order.buy_amount == old_order.sell_amount:
                tx1 = []
            else:
                child_order = {}
                if new_order.buy_amount > old_order.sell_amount:
                    child_order['buy_currency'] = new_order.buy_currency
                    child_order['sell_currency'] = new_order.sell_currency
                    child_order['buy_amount'] = new_order.buy_amount - old_order.sell_amount
                    child_order['sell_amount'] = child_order['buy_amount']*(new_order.sell_amount/new_order.buy_amount)*1.01
                    child_order['sender_pk'] = new_order.sender_pk
                    child_order['receiver_pk'] = new_order.receiver_pk
                    #child_order['tx_id'] = new_order.tx_id
                    child_order['creator_id'] = new_order.id
                    
                elif new_order.buy_amount < old_order.sell_amount:
                    child_order['buy_currency'] = old_order.buy_currency
                    child_order['sell_currency'] = old_order.sell_currency
                    child_order['sell_amount'] = old_order.sell_amount - new_order.buy_amount
                    child_order['buy_amount'] = child_order['sell_amount']*(old_order.buy_amount/old_order.sell_amount)*0.99
                    child_order['sender_pk'] = old_order.sender_pk
                    child_order['receiver_pk'] = old_order.receiver_pk
                    #child_order['tx_id'] = old_order.tx_id
                    child_order['creator_id'] = old_order.id
                    
                fill_order(child_order)
                
                
def get_algo_keys():
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the algorand public/private keys
    # fund here
    mnemonic_secret = 'monkey seed matter social panther soda amazing often honey fall denial bring combine donor concert step law among write bronze jazz smile stage ability cross'
    algo_sk = mnemonic.to_private_key(mnemonic_secret)
    algo_pk = mnemonic.to_public_key(mnemonic_secret)
    
    return algo_sk, algo_pk


def get_eth_keys(filename = "eth_mnemonic.txt"):
    from web3 import Web3
    w3 = Web3()
    
    with open(filename,'r') as file:
        mnemonic = file.read().strip()
    mnemonic = 'arrange youth please bracket gas honey matrix empower web boat hour key'
    eth_account.Account.enable_unaudited_hdwallet_features()
    #acct,mnemonic_secret = w3.eth.account.create_with_mnemonic()
    #print(mnemonic_secret)
    #eth_acct = eth_account.Account.from_mnemonic(mnemonic)
    acct = w3.eth.account.from_mnemonic(mnemonic)
    
    # TODO: Generate or read (using the mnemonic secret) 
    # the ethereum public/private keys
    eth_sk = acct._private_key
    eth_pk = acct._address

    return eth_sk, eth_pk
  
#def fill_order(order, txes=[]):
    # TODO: 
    # Match orders (same as Exchange Server II)
    # Validate the order has a payment to back it (make sure the counterparty also made a payment)
    # Make sure that you end up executing all resulting transactions!
    
#    pass
  
def execute_txes(txes):
    if txes is None:
        return True
    if len(txes) == 0:
        return True
    print( f"Trying to execute {len(txes)} transactions" )
    print( f"IDs = {[tx['order_id'] for tx in txes]}" )
    eth_sk, eth_pk = get_eth_keys()
    algo_sk, algo_pk = get_algo_keys()
    
    if not all( tx['platform'] in ["Algorand","Ethereum"] for tx in txes ):
        print( "Error: execute_txes got an invalid platform!" )
        print( tx['platform'] for tx in txes )

    algo_txes = [tx for tx in txes if tx['platform'] == "Algorand" ]
    eth_txes = [tx for tx in txes if tx['platform'] == "Ethereum" ]

    # TODO: 
    #       1. Send tokens on the Algorand and eth testnets, appropriately
    #          We've provided the send_tokens_algo and send_tokens_eth skeleton methods in send_tokens.py
    #       2. Add all transactions to the TX table
    
    send_tokens_algo(g.acl, algo_sk, algo_txes)
    send_tokens_eth(g.w3, eth_sk, eth_txes)
    
    g.session.add_all(algo_txes)
    g.session.add_all(eth_txes)
    g.session.commit()   

""" End of Helper methods"""
  
@app.route('/address', methods=['POST'])
def address():
    if request.method == "POST":
        content = request.get_json(silent=True)
        if 'platform' not in content.keys():
            print( f"Error: no platform provided" )
            return jsonify( "Error: no platform provided" )
        if not content['platform'] in ["Ethereum", "Algorand"]:
            print( f"Error: {content['platform']} is an invalid platform" )
            return jsonify( f"Error: invalid platform provided: {content['platform']}"  )
        
        if content['platform'] == "Ethereum":
            _, eth_pk = get_eth_keys()
            return jsonify( eth_pk )
        if content['platform'] == "Algorand":
            _, algo_pk = get_algo_keys()
            return jsonify( algo_pk )

@app.route('/trade', methods=['POST'])
def trade():
    print( "In trade", file=sys.stderr )
    connect_to_blockchains()
    #get_keys()
    
    #get algo keys
    algo_sk, algo_pk = get_algo_keys()
    #get eth keys
    eth_sk, eth_pk = get_eth_keys()
    
    if request.method == "POST":
        content = request.get_json(silent=True)
        columns = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform", "tx_id", "receiver_pk"]
        fields = [ "sig", "payload" ]
        error = False
        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        error = False
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                error = True
        if error:
            print( json.dumps(content) )
            return jsonify( False )
        
        # Your code here
        
        # 1. Check the signature
        sig = content.get('sig')
        payload = content.get('payload')
        
        # 2. Add the order to the table
        if check_sig(payload, sig):
            print('signature matched')
            # TODO: Add the order to the database
            #order = Order(sender_pk = payload.get('sender_pk'),
            #             receiver_pk = payload.get('receiver_pk'),
            #             buy_currency = payload.get('buy_currency'),
            #             sell_currency = payload.get('sell_currency'),
            #             buy_amount = payload.get('buy_amount'),
            #             sell_amount = payload.get('sell_amount'),
            #             tx_id = payload.get('tx_id'),
            #             )
            #g.session.add(order)
            #g.session.commit()
            # TODO: Fill the order
           
            order_dict = {'sender_pk': payload.get('sender_pk'),
                          'receiver_pk': payload.get('receiver_pk'),
                          'buy_currency':payload.get('buy_currency'),
                          'sell_currency':payload.get('sell_currency'),
                          'buy_amount':payload.get('buy_amount'),
                          'sell_amount':payload.get('sell_amount'),
                          'tx_id':payload.get('tx_id')}
        # 3a. Check if the order is backed by a transaction equal to the sell_amount (this is new)
            print('transaction_id: ' + order_dict['tx_id'] )
            if order_dict['sell_currency'] == 'Algorand':
                tx = g.icl.search_transactions(txid = order_dict['tx_id'])
                assert tx.amount == order_dict['sell_amount']
                tx_amount = tx.amount
                print('printing algorand tx')
                print(tx)
            elif order_dict['sell_currency'] == 'Ethereum':
                tx = g.w3.eth.get_transaction(order_dict['tx_id'])
                assert tx.value == order_dict['sell_amount']
                tx_amount = tx.value
                print('printing ethereum tx')
                print(tx)
            #if(order_dict['sell_amount'] == tx.order.sell_amount and order_dict['sender_pk'] == tx.order.sender_pk and tx.platform == tx.order.sell_currency ):
            if (tx_amount == order_dict['sell_amount']):
                print('trying to fill order')
                
                try:
                    fill_order(order_dict)
                    return jsonify( True)
                except Exception as e:
                  import traceback
                  print(traceback.format_exc())
                  print(e)  
 
                  
                #print('trying to execute order now')
                #
                #try:
                #    execute_txes(tx)
                #except Exception as e:
                #  import traceback
                #  print(traceback.format_exc())
                #  print(e)  
                  
            else:
                return jsonify( False )
        
        # 3b. Fill the order (as in Exchange Server II) if the order is valid
        
        # 4. Execute the transactions
        
        # If all goes well, return jsonify(True). else return jsonify(False)
        else:
            log_message(payload)
            return jsonify( False )


@app.route('/order_book')
def order_book():
    #fields = [ "buy_currency", "sell_currency", "buy_amount", "sell_amount", "signature", "tx_id", "receiver_pk", "sender_pk" ]
    
    orders = g.session.query(Order).all()
    orders_list = []
    
    for order in orders:
        orders_list.append({'sender_pk': order.sender_pk,
                            'receiver_pk':order.receiver_pk,
                            'buy_currency':order.buy_currency,
                            'sell_currency':order.sell_currency,
                            'buy_amount':order.buy_amount,
                            'sell_amount':order.sell_amount,
                            'signature':order.signature,
                            'tx_id':order.tx_id})
    
    return json.dumps({'data':orders_list})

if __name__ == '__main__':
    app.run(port='5002')