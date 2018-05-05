# Streaming Data Payment Protocol(SDPP)

An application-layer client-server protocol that enables purchase of data streams (such as IoT sensor data) through cryptocurrency, with invoice and receipts stored in an immutable distributed ledger. It is implemented using Python.

This is release 1.0, we are still working to improve it. 

## More Reading
[Current draft of the paper describing this protocol](https://github.com/ANRGUSC/SDPP/blob/master/documents/streaming-data-payment-protocol.pdf)

## Requirements
- [pyota](https://pyota.readthedocs.io/en/latest/) - Python library for the IOTA Core 
- [pycrypto](https://www.dlitz.net/software/pycrypto/) - Python Cryptography Toolkit

## Instructions
- git clone https://github.com/ANRGUSC/SDPP.git
- cd SDPP/
- ./seller.py \**ip_address*\*  \**port*\*
- ./buyer.py \**ip_address*\*  \**port*\*
- Then please follow the instructions on your console!

## Version 1.0
- Implemented using IOTA
- Encryption using Shared Secret Key
- Seller sends its public-key to the buyer along with the "Menu" (but in practical scenarios, it is made available openly)

## Future Plans
- Trying the protocol on Blockchain based cryptocurrencies including Ethereum
- Integration with Hyperledger Fabric
- A more general, clean architecture (such as based on [Blockstack](https://blockstack.org/)) 
- Incorporating TLS
- Implementation with mobile device

## License
Copyright (c) 2018, Autonomous Networks Research Group, USC. See [this](https://github.com/ANRGUSC/SDPP/blob/master/LICENSE.txt) file for more details.
