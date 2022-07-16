from flask import Flask, request, jsonify
from flask_restful import Api
import json
import eth_account
import algosdk

app = Flask(__name__)
api = Api(app)
app.url_map.strict_slashes = False

@app.route('/verify', methods=['GET','POST'])
def verify():
    content = request.get_json(silent=True)
    platform = content['payload']['platform'] 
    message = content['payload']['message'] 
    pk = content['payload']['pk'] 
    sig = content['sig']
    payload = json.dumps(content['payload'])
    response = False
    
    if platform=='Ethereum':
        eth_encoded_msg = eth_account.messages.encode_defunct(text=payload)
        if eth_account.Account.recover_message(eth_encoded_msg,signature=sig) == pk:
            response = True

    if platform=='Algorand':
        if algosdk.util.verify_bytes(payload.encode('utf-8'),sig,pk):
            response = True

    return jsonify(response)

if __name__ == '__main__':
    app.run(port='5002')