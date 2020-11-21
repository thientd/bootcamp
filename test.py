import requests
rq = requests.post("http://localhost:8089/")
print(rq.text)
