import requests
import json

def pin_to_ipfs(data):
	assert isinstance(data,dict), f"Error pin_to_ipfs expects a dictionary"
	#YOUR CODE HERE
	response = requests.post('https://ipfs.infura.io:5001/api/v0/add', files=data)
	cid = response.json()['Hash']
	return cid

def get_from_ipfs(cid,content_type="json"):
	assert isinstance(cid,str), f"get_from_ipfs accepts a cid in the form of a string"
	#YOUR CODE HERE	
	params = (
   	('arg', cid),
	)

	response = requests.post('https://ipfs.infura.io:5001/api/v0/cat', params=params)
	data = {'file': str(response.text)}
	assert isinstance(data,dict), f"get_from_ipfs should return a dict"
	return data