Streaming Data Payment Protocol(SDPP) - An application-layer client-server protocol that enables purchase of data streams (such as IoT sensor data) through cryptocurrency, with invoice and receipts stored in an immutable distributed ledger. It is implemented using IOTA. 

For the current draft of the paper describing this protocol, please see the documents folder. 

To try it out,

1) git clone https://github.com/ANRGUSC/SDPP.git
2) cd SDPP/
3) python seller.py "ip" "port"
4) python buyer.py "ip" "port"

**Dependencies**
 - pyota: https://github.com/iotaledger/iota.lib.py
 - pycrypto
