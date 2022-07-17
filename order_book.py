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
    order_obj = Order( sender_pk=order['sender_pk'],receiver_pk=order['receiver_pk'], buy_currency=order['buy_currency'], sell_currency=order['sell_currency'], buy_amount=order['buy_amount'], sell_amount=order['sell_amount'] )
    session.add(order_obj)
    session.commit()

    matched_order = session.query(Order).filter(Order.filled==None,\
                                       Order.buy_currency == order_obj.sell_currency,\
                                       Order.sell_currency == order_obj.buy_currency,\
                                       Order.sell_amount/Order.buy_amount >= order_obj.buy_amount/order_obj.sell_amount).first()

    if matched_order != None:
        matched_order.filled = datetime.now()
        order_obj.filled = matched_order.filled
        
        matched_order.counterparty_id = order_obj.id
        order_obj.counterparty_id = matched_order.id

            
        if order_obj.buy_amount > matched_order.sell_amount:
                new_order = Order(sender_pk = order_obj.sender_pk,receiver_pk = order_obj.receiver_pk, \
                                  buy_currency = order_obj.buy_currency, sell_currency = order_obj.sell_currency, \
                                  buy_amount = order_obj.buy_amount - matched_order.sell_amount, \
                                  sell_amount = (order_obj.buy_amount - matched_order.sell_amount)* order_obj.sell_amount / order_obj.buy_amount,\
                                  creator_id = order_obj.id)
                print("partially filled, new_order.buy_amount > matched_order.sell amount, creator_id =", new_order.creator_id)
                session.add(new_order)
                session.commit()

                        

                    
        if matched_order.buy_amount > order_obj.sell_amount:
                new_order = Order(sender_pk = matched_order.sender_pk,receiver_pk = matched_order.receiver_pk, \
                                  buy_currency =matched_order.buy_currency, sell_currency = matched_order.sell_currency, \
                                  buy_amount = matched_order.buy_amount - order_obj.sell_amount, \
                                  sell_amount= (matched_order.buy_amount - order_obj.sell_amount) * matched_order.sell_amount / matched_order.buy_amount,\
                                  creator_id = matched_order.id)
                print("partially filled, matched_order.buy_amount>new_order.sell_amount, creator_id =", new_order.creator_id)
                
                session.add(new_order)
                session.commit()

    pass