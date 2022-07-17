from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from datetime import datetime

from models import Base, Order
engine = create_engine('sqlite:///orders.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

def process_order(order):
    #Your code here
    order["filled"]=None
    order["counterparty_id"]=None
    order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'] )
    session.add(order_obj)
    session.commit()
    lastInserted=session.query(Order).all()[len(session.query(Order).all())-1]
    queryResults = session.query(Order).all()
    for existingOrder in queryResults:
        if (existingOrder.filled==None and existingOrder.buy_currency==order["sell_currency"] and existingOrder.sell_currency==order["buy_currency"] and (existingOrder.sell_amount/existingOrder.buy_amount)>=(order["buy_amount"]/order["sell_amount"])):
            existingOrder.filled=datetime.now()
            lastInserted.filled=datetime.now()
            lastInserted.counterparty_id=existingOrder.id
            existingOrder.counterparty_id=lastInserted.id
            # print(existingOrder.filled, existingOrder.counterparty_id, )
            if(existingOrder.sell_amount<lastInserted.buy_amount):
                nOrder = {}
                nOrder["created_by"]=lastInserted.id
                nOrder['sender_pk'] = lastInserted.sender_pk
                nOrder['receiver_pk'] = lastInserted.receiver_pk
                nOrder['buy_currency'] = lastInserted.buy_currency
                nOrder['sell_currency'] = lastInserted.sell_currency
                nOrder['sell_amount'] = lastInserted.sell_amount
                nOrder['buy_amount'] = (lastInserted.sell_amount-existingOrder.sell_amount)
                process_order(nOrder)
            if(lastInserted.sell_amount<existingOrder.buy_amount):
                nOrder = {}
                nOrder["created_by"]=existingOrder.id
                nOrder['sender_pk'] = existingOrder.sender_pk
                nOrder['receiver_pk'] = existingOrder.receiver_pk
                nOrder['buy_currency'] = existingOrder.buy_currency
                nOrder['sell_currency'] = existingOrder.sell_currency
                nOrder['sell_amount'] = existingOrder.sell_amount
                nOrder['buy_amount'] = (existingOrder.sell_amount-lastInserted.sell_amount)
                process_order(nOrder)
            break