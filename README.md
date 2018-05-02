# Streaming Data Payment Protocol(SDPP)

An application-layer client-server protocol that enables purchase of data streams (such as IoT sensor data) through cryptocurrency, with invoice and receipts stored in an immutable distributed ledger. It is implemented using Python.

## More Reading
For the current draft of the paper describing this protocol, please see the documents folder. 

## Requirements
- pip install pyota - [More here](https://pyota.readthedocs.io/en/latest/)
- pip install pycrypto

## Version 1
- Implemented using IOTA
- Encryption using Shared Secret Key
- Seller sends its public-key to the buyer along with the "Menu"(but in practical scenarios, it is made available openly)

## Future plans
- Trying the protocol on Blockchain based cryptocurrencies
- Integration with Hyperledger Fabric
- A more general, clean architecture(based on [Blockstack](https://blockstack.org/)) 
- Incorporating TLS
- Implementation with mobile device

