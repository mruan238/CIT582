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
import sys

from models import Base, Order, Log
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)

app = Flask(__name__)

@app.before_request
def create_session():
    g.session = scoped_session(DBSession)

@app.teardown_appcontext
def shutdown_session(response_or_exc):
    sys.stdout.flush()
    g.session.commit()
    g.session.remove()


""" Suggested helper methods """

def check_sig(payload,sig):
    result_check_sig = False
    pm = payload['platform']
    sk = sig
    pk = payload['pk']
    message = json.dumps(payload)
    
    if pm == "Ethereum":
        eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
        recovered_pk = eth_account.Account.recover_message(eth_encoded_msg,signature=sk)
        if(recovered_pk == pk):
            result_check_sig = True
            print( "Eth sig verifies!" )    
    elif pm == "Algorand":
        result_check_sig = algosdk.util.verify_bytes(message.encode('utf-8'),sk,pk)
        if(result_check_sig):
            print( "Algo sig verifies!" )
    else:
        print("invalid input")

    print(" this is jsonify(result_check_sig) = ",jsonify(result_check_sig))
    return jsonify(result_check_sig)


def fill_order(order,txes=[]):
    order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'] )
    g.session.add(order_obj)
    g.session.commit()
    matched_order = g.session.query(Order).filter(Order.filled==None,\
                                       Order.buy_currency == order_obj.sell_currency,\
                                       Order.sell_currency == order_obj.buy_currency,\
                                       Order.sell_amount/Order.buy_amount >= order_obj.buy_amount/order_obj.sell_amount).first()
    if matched_order != None:
        matched_order.filled = datetime.now()
        order_obj.filled = matched_order.filled
        
        matched_order.counterparty_id = order_obj.id
        order_obj.counterparty_id = matched_order.id
            
        if order_obj.buy_amount > matched_order.sell_amount:
                new_order = Order(sender_pk = order_obj.sender_pk,receiver_pk = order_obj.receiver_pk,                                   buy_currency = order_obj.buy_currency, sell_currency = order_obj.sell_currency,                                   buy_amount = order_obj.buy_amount - matched_order.sell_amount,                                   sell_amount = (order_obj.buy_amount - matched_order.sell_amount)* order_obj.sell_amount / order_obj.buy_amount,                                  creator_id = order_obj.id)
                print("partially filled, new_order.buy_amount > matched_order.sell amount, creator_id =", new_order.creator_id)
                g.session.add(new_order)
                g.session.commit()
                 
        if matched_order.buy_amount > order_obj.sell_amount:
                new_order = Order(sender_pk = matched_order.sender_pk,receiver_pk = matched_order.receiver_pk,                                   buy_currency =matched_order.buy_currency, sell_currency = matched_order.sell_currency,                                   buy_amount = matched_order.buy_amount - order_obj.sell_amount,                                   sell_amount= (matched_order.buy_amount - order_obj.sell_amount) * matched_order.sell_amount / matched_order.buy_amount,                                  creator_id = matched_order.id)
                print("partially filled, matched_order.buy_amount>new_order.sell_amount, creator_id =", new_order.creator_id)
                
                g.session.add(new_order)
                g.session.commit()
    pass
  
def log_message(d):
    # Takes input dictionary d and writes it to the Log table
    # Hint: use json.dumps or str() to get it in a nice string form
    order =  json.dumps(d)
    g.session.add(Log(message=order))
    g.session.commit()
    pass

""" End of helper methods """



@app.route('/trade', methods=['POST'])
def trade():
    print("In trade endpoint")
    if request.method == "POST":
        content = request.get_json(silent=True)
        print( f"content = {json.dumps(content)}" )
        columns = [ "sender_pk", "receiver_pk", "buy_currency", "sell_currency", "buy_amount", "sell_amount", "platform" ]
        fields = [ "sig", "payload" ]

        for field in fields:
            if not field in content.keys():
                print( f"{field} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
        
        for column in columns:
            if not column in content['payload'].keys():
                print( f"{column} not received by Trade" )
                print( json.dumps(content) )
                log_message(content)
                return jsonify( False )
            
        #Your code here
        #Note that you can access the database session using g.session

        # TODO: Check the signature
    result_check = False
    payload = content['payload']
    sig = content['sig']
    result_check = check_sig(payload,sig)
        # TODO: Add the order to the database
    if(result_check):
        order = {}
        order['sender_pk'] = payload['sender_pk']
        order['receiver_pk'] = payload['receiver_pk']
        order['buy_currency'] = payload['buy_currency']
        order['sell_currency'] = payload['sell_currency']
        order['buy_amount'] = payload['buy_amount']
        order['sell_amount'] = payload['sell_amount']
        order['signature'] = sig
        # TODO: Fill the order
        fill_order(order,txes=[])
    else:
        log_message(content)
        # TODO: Be sure to return jsonify(True) or jsonify(False) depending on if the method was successful
    if(result_check):
        return jsonify(True)
    else:
        return jsonify(False)

@app.route('/order_book')
def order_book():
    #Your code here
    #Note that you can access the database session using g.session
    temp = g.session.query(Order)
    mydict = []
    for myquery in temp.all():
        myorder = {}
        myorder['buy_currency'] = getattr(myquery,'buy_currency')
        myorder['sell_currency'] =  getattr(myquery,'sell_currency')
        myorder['buy_amount'] =  getattr(myquery,'buy_amount')
        myorder['sell_amount'] =  getattr(myquery,'sell_amount')
        myorder['sender_pk'] =  getattr(myquery,'sender_pk')
        myorder['receiver_pk'] =  getattr(myquery,'receiver_pk')
        myorder['signature'] =  getattr(myquery,'signature')
        mydict.append(myorder)
    result = { 'data': mydict } 
    #print(result_order_book) 
    print(" this is jsonify(result_order_book) = ",jsonify(result))
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')