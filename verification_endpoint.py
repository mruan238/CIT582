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
    content = request.get_json(silent=True, force=True)
    #Check if signature is valid
    print(content)
    if content == None:
        return jsonify("No json data is sent.")
    sig = content.get('sig')
    payload = content.get('payload')
    message = payload.get('message')
    pk = payload.get('pk')
    platform = payload.get('platform')
    if platform == "Ethereum":
        encoded_msg = eth_account.messages.encode_defunct(text=json.dumps(payload))
        result = eth_account.Account.recover_message(encoded_msg,signature=sig) == pk
    else:
        result = algosdk.util.verify_bytes(json.dumps(payload).encode('utf-8'), sig, pk)
    return jsonify(result)


if __name__ == '__main__':
    app.run(port='5002')