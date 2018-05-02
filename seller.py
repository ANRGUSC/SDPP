# Copyright (c) 2018, Autonomous Networks Research Group. All rights reserved.
#     Contributor: Rahul Radhakrishnan
#     Read license file in main directory for more details  

import socket
import sys
from thread import *
import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
from Crypto import Random
from Crypto.Cipher import AES
import base64
import os
import hashlib
import iota
import logging
import json
import pprint


# Seller's Keys
key = RSA.generate(2048)
seller_public_key = key.publickey().exportKey('OpenSSH')

# Establish Connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])
server.bind((IP_address, Port))

# Number of buyers the seller can handle. Can be increased.
server.listen(500)

# IOTA Related
seed = ""
client = "http://node02.iotatoken.nl:14265"
iota_api = iota.Iota(client, seed)

# Set Values
signature_required = 1
payment_granularity = 5
payment_address = iota_api.get_new_addresses(count=1)
payment_address = str(payment_address['addresses'][0].address)
bs = 32

# Info to be received from buyer
invoice_address = ""
encrypt_pub_key = ""
data_type = ""
quantity = 0
currency = "iota"
secret_key = ""


# Tangle logs
#logger = create_logger(severity=logging.DEBUG)
#logger = create_logger(logging.NOTSET)
#iota_api.adapter.set_logger(logger)


def create_logger(severity):
    logging.basicConfig(
        level=severity,
        format="[%(asctime)s] %(levelname)s %(module)s:%(funcName)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)

def signData(plaintext):
    """
    Signs the Data
    :param plaintext: String to be signed
    :return: signature<Tuple>
    """
    hash = MD5.new(plaintext).digest()
    signature = key.sign(hash, '')
    return signature

def verifySignature(message, signature):
    """
    Verifies the Signature
    :param message: String to be verified
    :param signature: Signature provided by the Buyer
    :return: True/False
    """
    hash = MD5.new(message).digest()
    return signature_pub_key.verify(hash, signature)

def _pad(s):
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def encrypt(raw):
    """
    AES based encryption(using Session Key)
    :param enc: String to be encrypted
    :return: Encrypted Data<String>
    """
    raw = _pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

def prepareJSONstring(message_type, data, signature=None, verification=None):
    """
   Prepares the JSON message format to be sent to the Buyer
   :param message_type: MENU/SESSION_KEY/DATA/DATA_INVOICE
   :param data: Corresponding data
   :param signature: Signed Data
   :param verification: Address or the transaction ID in Tangle/Blockchain
   :return: JSON dictionary
    """
    json_data = {}

    json_data['message_type'] = message_type
    json_data['data'] = data

    if signature:
        json_data['signature'] = signature
    else:
        json_data['signature'] = ""
    if verification:
        json_data['verification'] = verification
    else:
        json_data['verification'] = ""

    return json.dumps(json_data)

def sendTransaction(transaction):
    try:
        bundle = iota_api.send_transfer(depth=2, transfers=[transaction])
        url = "https://thetangle.org/bundle/" + str(bundle["bundle"].hash)
        print url
        #logger.info(url)
        return str(iota_api.find_transactions([bundle["bundle"].hash])['hashes'][0])
    except iota.adapter.BadApiResponse as error:
        #logger.error(error)
        return False

def prepareTransaction(value=0, message=None):
    """
    Prepares the transaction to be made through the distributed ledger
    :param message: Message for the payment
    :param value: Amount of cryptocurrencies to be sent
    :return: Transaction ID/ Address/ Transaction hash
    """
    if message:
        message = iota.TryteString.from_string(message)
    tag = iota.Tag(b"SDPPSELLER")

    transaction = iota.ProposedTransaction(
        address=invoice_address,
        value=value,
        message=message,
        tag=tag
    )
    return sendTransaction(transaction)

def generateSecretKey():
    """
    Generates the Session key to be used for Data Transfer
    :return: Session Key<String>
    """
    global secret_key
    secret_key = hashlib.sha256(os.urandom(16)).digest()
    return str(encrypt_pub_key.encrypt(secret_key, 32))


def dataTransfer():
    """
    Actual Data Transfer happens here
    :return: Remaining data for which money is yet to be paid
    """
    with open('menu.json') as myfile:
        menu = myfile.read()
        menu = json.loads(menu)
        cost = int(menu['menu'][data_type])

    filepath = "actual_data/"+data_type+".txt"
    with open(filepath) as f:
        lines = f.read().splitlines()
    remaining = quantity
    counter = 1

    print "--------Data Transfer Starts---------"
    while counter <= quantity:
        data = {}
        data['data'] = lines[counter-1]
        transaction_hash = None
        message_type = "DATA"

        # Record in the tangle/blockchain
        if counter%payment_granularity == 0:
            remaining = remaining - payment_granularity
            data_invoice = "Sent: " + str(payment_granularity)
            data_invoice += "\nCost: " + str(payment_granularity*cost)
            print "Invoice recorded: ",
            transaction_hash = prepareTransaction(message=data_invoice)
            data['invoice'] = str(payment_granularity*cost)
            message_type = "DATA_INVOICE"

        data = json.dumps(data)
        # Encrypt using the Session Key
        data = encrypt(data)
        signature = signData(data)
        json_string = prepareJSONstring(message_type, data, signature, transaction_hash)

        # print "Data " + str(counter) + " sent"
        # print pprint.pprint(json.loads(json_string))

        conn.send(json_string)

        message = conn.recv(2048)
        message = json.loads(message)
        data = message['data']

        # If Nack - send the packet again
        if data == "0":
            continue

        # Verify Signature of the Buyer
        if signature_required == 1:
            recv_signature = message['signature']
            if verifySignature(data, recv_signature) is not True:
                print "Invalid Signature, closing the connection.."
                conn.close()
                exit()

        # If it is a payment ack, check if the transaction is present
        recv_message_type = message['message_type']
        if recv_message_type == "PAYMENT_ACK":
            #TODO verify if the buyer has made the payment
            verify_addr = message['verification']

        # print "Ack " + str(counter) + " received"
        # print pprint.pprint(message)

        counter = counter + 1
    print "--------Data Transfer Ends---------"
    return remaining

def receiveOrder():
    """
    Process the order from the buyer and stores other informations provided by the buyer
    :return: None
    """
    global invoice_address, encrypt_pub_key, signature_pub_key, data_type, quantity, currency
    message = conn.recv(2048)
    message = json.loads(message)

    data = json.loads(message['data'])

    # get all the information
    data_type = str(data['data_type'])
    quantity = int(data['quantity'])
    currency = data['currency']
    encrypt_pub_key = RSA.importKey(data['encryption-key'])
    signature_pub_key = RSA.importKey(data['signature-key'])
    invoice_address = iota.Address(str(data['address']))

    buyer_order = str(data_type) + ' ' + str(quantity)

    if verifySignature(buyer_order, message['signature']) is not True:
        print "Invalid Signature, closing the connection.."
        conn.close()
        exit()

    # TODO verify if the buyer has registered in the blockchain/tangle
    verify_addr = message['verification']
    # verifyTramsaction(verify_addr, message=buyer_order)

    session_key = generateSecretKey()
    json_string = prepareJSONstring("SESSION_KEY", session_key)
    conn.send(json_string)

def prepareMenuData():
    with open('menu.json') as myfile:
        menu = myfile.read()
        menu = json.loads(menu)
        menu['payment-address'] = payment_address
        menu['payment-granularity'] = str(payment_granularity)
        menu['signature-required'] = str(signature_required)
        menu['public-key'] = seller_public_key
        menu = json.dumps(menu)

    signature = signData(menu)

    return prepareJSONstring("MENU", menu, signature)

def sendMenu():
    """
    Send the Menu with other details to the Buyer
    :return: None
    """
    json_string = prepareMenuData()
    conn.send(json_string)


# checks whether sufficient arguments have been provided
if len(sys.argv) != 3:
    print "Correct usage: script, IP address, port number"
    exit()

def clientthread(conn, addr):
    sendMenu()
    receiveOrder()
    remaining  = dataTransfer()
    message = conn.recv(2048)
    message = json.loads(message)

    if signature_required == 1:
        if verifySignature(message['data'], message['signature']) is not True:
            print "Invalid Signature, closing the connection.."
            conn.close()
            exit()

    if remaining > 0:
        #TODO verify the transaction
        verify_addr = message['verification']

    print "\nWaiting for other buyers!"

while True:

    # receive the address here
    conn, addr = server.accept()

    # prints the address of the buyer that just connected
    print addr[0] + " connected"

    # creates an individual thread for every buyer
    start_new_thread(clientthread, (conn, addr))

conn.close()
server.close()
