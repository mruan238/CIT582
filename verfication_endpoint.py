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
    result = False
    content = request.get_json(silent=True)    
    sk = content['sig']
    payload = content['payload']
    platform = content['payload']['platform']
    message = json.dumps(payload)
    pk = payload['pk']

    
    #1. Verifying an endpoint for verifying signatures for ethereum
    if platform == "Ethereum":

        #eth_account.Account.enable_unaudited_hdwallet_features()
        #acct, mnemonic = eth_account.Account.create_with_mnemonic()

        #eth_pk = acct.address
        #eth_sk = acct.key

        #payload = "Sign this!"

        eth_encoded_msg = eth_account.messages.encode_defunct(text=message)
        #eth_sig_obj = eth_account.Account.sign_message(eth_encoded_msg,sk)
        #print( eth_sig_obj.messageHash )
        recovered_pk = eth_account.Account.recover_message(eth_encoded_msg,signature=sk)
        if(recovered_pk ==pk):
            result = True
            print( "Eth sig verifies!" )    
    
    #2. Verifying an endpoint for verifying signatures for Algorand
    elif platform == "Algorand":
        result = algosdk.util.verify_bytes(message.encode('utf-8'),sk,pk)
        if(result):
            print( "Algo sig verifies!" )
    
    #3. Check for invalid input
    else:
        print("invalid input")

    #Check if signature is valid
    #result = True #Should only be true if signature validates
    return jsonify(result)

if __name__ == '__main__':
    app.run(port='5002')