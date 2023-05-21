import http
import requests


url = "http://127.0.0.1:80/data.json"

response = requests.get(url)

response_json = response.json()

print(response_json)
print(response.headers)

http_headers = response.headers
clen = 0  
for attribute in http_headers:
    print(attribute,'-',http_headers[attribute].__len__())
    if attribute == 'Content-Length':
        clen = clen + attribute.__len__()
    clen = clen + http_headers[attribute].__len__() + 2 #for the \r\n

print(clen)



'''
HTTP/1.1 200 OK\r\nDate: Tue, 04 Apr 2023 13:58:37 GMT\r\nServer: Apache/2.4.41 (Ubuntu)\r\nLast-Modified: Wed, 15 Mar 2023 15:38:25 GMT\r\nETag: "42-5f6f2228b5ba5"\r\nAccept-Ranges: bytes\r\nContent-Length: 66\r\nAccess-Control-Allow-Headers: origin, x-requested-with, content-type, authorization\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Origin: *\r\nKeep-Alive: timeout=5, max=100\r\nConnection: Keep-Alive\r\nContent-Type: application/json\r\n\r\n[{"id": 123,"age": 29,"name": "Da Vinchi"}]
'''