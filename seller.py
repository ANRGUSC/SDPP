# Copyright (c) 2018, Autonomous Networks Research Group. All rights reserved.
#     contributor: Rahul Radhakrishnan
#     Read license file in main directory for more details  
 

import socket
import sys
from thread import *
import json
import logging
import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
import pprint
import iota
import time

def create_logger(severity):
    logging.basicConfig(
        level=severity,
        format="[%(asctime)s] %(levelname)s %(module)s:%(funcName)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)

# prepares the json data that needs to be sent to the seller
def prepareJSONstring(data=None, ack=None, key=None, tangle_info=None, signature=None):
    json_data = {}
    if data:
        json_data['data'] = data
    else:
        json_data['data'] = ""
    if ack:
        json_data['ack'] = ack
    else:
        json_data['ack'] = ""
    if key:
        json_data['key'] = key
    else:
        json_data['key'] = ""
    if tangle_info:
        json_data['tangle_info'] = tangle_info
    else:
        json_data['tangle_info'] = ""
    if signature:
        json_data['signature'] = signature
    else:
        json_data['signature'] = ""

    return json.dumps(json_data)

def verifySignature(order, pub_key, signature):
    hash = MD5.new(order).digest()
    return pub_key.verify(hash, signature)


'''
Need to check the actual data in the transaction
Assumed it will get confirmed later
'''

def verifyTramsaction(verify_addr, message="", value=""):
    transaction = iota_api.get_trytes(hashes=[verify_addr])
    if not transaction:
        print "Buyer didn't record the transaction in the tangle"

    if message != "":
        message_tangle = iota.Transaction.from_tryte_string(transaction['trytes'][0])\
                    .signature_message_fragment.as_string()

        if message_tangle.split('\n')[0] != str(message):
            print "Buyer didn't record the actual data in the tangle"

    if value != "":
        value_ = iota.Transaction.from_tryte_string(transaction['trytes'][0]).value
        print value, value_
        if str(value_) != str(value):
            print "User didn't send the actual money"


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

def prepareTransaction(addr="", value=0, message=""):
    if message != "":
        message = iota.TryteString.from_string(message)
    tag = iota.Tag(b"SDPPSELLER")

    target_addr = iota.Address(addr)

    transaction = iota.ProposedTransaction(
        address=target_addr,
        value=value,
        message=message,
        tag=tag
    )

    transaction_hash = sendTransaction(transaction)
    if not transaction_hash:
        return False
    return transaction_hash

def generateAndAttach():
    addr = iota_api.get_new_addresses(count=1)
    addr = addr['addresses'][0].address
    # target_addr = iota.Address(addr)

    val = iota_api.get_transactions_to_approve(2)

    branch_transaction = val['branchTransaction']
    trunk_transaction = val['trunkTransaction']

    iota_api.attach_to_tangle(trunk_transaction, branch_transaction, [addr])

    return str(addr)

'''
Receive the order from the buyer, quantity and the data_request
Gets the public key of the buyer
Verifies the Tangle address in which the buyer has posted order information

'''

def receiveOrder():
    message = conn.recv(2048)
    message = json.loads(message)
    #pprint.pprint(message)

    pub_key = RSA.importKey(message['key'])
    buyer_order = message['data']

    verifySignature(buyer_order, pub_key, message['signature'])

    # verify if this is verified
    verify_addr = message['tangle_info']
    verifyTramsaction(verify_addr, message=buyer_order)

    buyer_order = buyer_order.split(" ")
    quantity = buyer_order[1]
    buyer_request = buyer_order[0]

    return int(quantity), buyer_request, pub_key


'''
Confirms the buyer's order
Send "K" value to the buyer for the IOTA payment
Generates the secret key and encrypts with buyer's public_key
Generate the address, attaches to tangle so that buyer's payment can be received 

'''
def confirmOrder(buyer_pub_key):

    encrypted_data = str(buyer_pub_key.encrypt(str(k), 32))
    addr = generateAndAttach()
    money_addr = addr
    json_string = prepareJSONstring(data=encrypted_data, tangle_info=addr)
    conn.send(json_string)


def dataTransfer(quantity, buyer_request, buyer_pub_key):

    filepath = "actual_data/"+buyer_request+".txt"
    with open(filepath) as f:
        lines = f.read().splitlines()
    last_counter = 0
    counter = 1
    while counter <= quantity:
        encrypted_data = str(buyer_pub_key.encrypt(lines[counter-1], 32))
        if counter%k == 0:
            transaction_hash = prepareTransaction(money_addr)
            addr = generateAndAttach()
            json_string = prepareJSONstring(data=encrypted_data, tangle_info=addr)
        else:
            json_string = prepareJSONstring(data=encrypted_data)

        conn.send(json_string)

        message = conn.recv(2048)
        message = json.loads(message)
        #pprint.pprint(message)

        if message['ack'] != 1 or not verifySignature(str(message['ack']), buyer_pub_key, message['signature']):
            # resend the data, no ack
            continue

        if counter == quantity:
            val = counter - last_counter
            val = str(val)
            verifyTramsaction(message['tangle_info'], value=val, message="")
            break

        if counter % k == 0:
            verifyTramsaction(message['tangle_info'], value=str(k), message="")
            last_counter = counter
        counter = counter + 1


# checks whether sufficient arguments have been provided
if len(sys.argv) != 3:
    print "Correct usage: script, IP address, port number"
    exit()

k = 4

money_addr = ""

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# takes the first argument from command prompt as IP address
IP_address = str(sys.argv[1])

# takes second argument from command prompt as port number
Port = int(sys.argv[2])

server.bind((IP_address, Port))

# Number of buyers the seller can handle.
# #### Limit can be modified. What's the maximum? ####
server.listen(500)


seed = ""
client = "http://node02.iotatoken.nl:14265"
iota_api = iota.Iota(client, seed)
#logger = create_logger(severity=logging.DEBUG)
#logger = create_logger(logging.NOTSET)

#iota_api.adapter.set_logger(logger)


def clientthread(conn, addr):
    # sends a message to the client whose user object is conn


    # send the Menu here
    with open('menu.json') as myfile:
        menu = myfile.read()

    menu = "\nThanks for reaching out to us!!\n\n" + str(menu) + '\n' + \
                "Please type your option \"<data_request> <quantity>\"" + '\n'
    json_string = prepareJSONstring(data=menu)
    conn.send(json_string)

    while True:
        quantity, buyer_request, buyer_pub_key = receiveOrder()

        confirmOrder(buyer_pub_key)

        dataTransfer(quantity, buyer_request, buyer_pub_key)

        print "Done!"
        break

while True:

    # receive the address here
    conn, addr = server.accept()

    # prints the address of the user that just connected
    print addr[0] + " connected"

    # creates an individual thread for every user
    start_new_thread(clientthread, (conn, addr))

conn.close()
server.close()
