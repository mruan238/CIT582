from web3 import Web3
from vyper import compile_code, compile_codes
from os import path 
import json
import requests

#For our tests, we'll use a local Ethereum testing environment.
#If you want to deploy to a live network (e.g. Mainnet or a testnet) simply replace this line with the URL of a real node.
#The tester enviroment also comes with an array of pre-funded accounts
#w3.eth.accounts[0]
#w3.eth.accounts[1]
#etc
w3 = Web3(Web3.EthereumTesterProvider())

def deploy_nft(contract_file,name,symbol,minter_address):
	"""
	Deploy a contract to the blockchain (this assumes a valid web3 instance w3 as a global variable)
	contract_file should be the path to a vyper file containing the contract
	name is the name of the token being deployed
	symbol is the symbol of the token being deployed
	minter_address is the account that is deploying the contract, this account pays the gas and will be set as the "minter" within the contract

	Returns: a contract object
	"""
	if not path.exists(contract_file):
		print( f"Error in deploy_contract: {contract_file} does not exist" )
		return None

	with open(contract_file,"r") as f:
		contract_source=f.read()

	#Compile the contract with Vyper
	contract_dict = compile_codes(contract_sources={contract_file:contract_source},output_formats=["bytecode","abi"])

	#Create a contract object
	ERC721_contract = w3.eth.contract(abi=contract_dict[contract_file]['abi'], bytecode=contract_dict[contract_file]['bytecode'])

	# Submit the transaction that deploys the contract
	#Note that unless you change the code, this will be the only address allowed to mint NFTs from this contract
	tx_hash = ERC721_contract.constructor(name,symbol).transact({"from":minter_address}) 

	# Wait for the transaction to be mined, and get the transaction receipt
	tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

	#Get the contract object from the chain (including the deployed address)
	ERC721_contract = w3.eth.contract(abi=contract_dict[contract_file]['abi'], address=tx_receipt.contractAddress )
	
	#Return the contract object
	return ERC721_contract

def pin_to_ipfs(data):
    assert isinstance(data, dict), f"Error pin_to_ipfs expects a dictionary"
    files = {
        'file': (json.dumps(data)),
    }
    response = requests.post('https://ipfs.infura.io:5001/api/v0/add', files=files)
    p = response.json()
    cid = p['Hash']
    return cid


def mint_nft(nft_contract,tokenId,metadata,owner_address,minter_address):
	"""
	nft_contract: a deployed contract
	tokenId: the id of the token being minted (this is a uint256)
	metadata: a (JSONifiable) python dict containing metadata
	owner_address: the owner of the newly minted token (whom the token is being minted "to")
	minter_address: the owner of the token contract, i.e., the account calling the "mint" procedure
	"""
	assert isinstance(metadata,dict), f"mint_nft expects a metadata dictionary"	

	#YOUR CODE HERE	
	cid = pin_to_ipfs(metadata)
	cid = "ipfs://" + cid

	#Step 2:Call "mint" on the contract, set tokenURI to be "ipfs://{CID}" where CID was obtained from step 1
	result = nft_contract.functions.mint(owner_address, tokenId, cid).transact({"from":minter_address})


	
