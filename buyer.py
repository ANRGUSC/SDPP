# Copyright (c) 2018, Autonomous Networks Research Group. All rights reserved.
#     contributor: Rahul Radhakrishnan
#     Read license file in main directory for more details  

import socket
import json
import sys
import logging
import Crypto.Hash.MD5 as MD5
import Crypto.PublicKey.RSA as RSA
import ast
import pprint
import iota


# validates the order placed by the buyer
def validate_user_input(input_str, available_data):
    input_str = input_str.split(" ")
    if input_str[0] not in available_data.keys():
        return False
    return True

# prepares the json data that needs to be sent to the seller
def prepareJSONstring(message_type, data, signature=None, verification=None):
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

# signs the given string for integrity check
def signData(key, plaintext):
    hash = MD5.new(plaintext).digest()
    signature = key.sign(hash, '')
    return signature

def create_logger(severity):
    logging.basicConfig(
        level=severity,
        format="[%(asctime)s] %(levelname)s %(module)s:%(funcName)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    return logging.getLogger(__name__)

def sendTransaction(transaction):
    try:
        bundle = iota_api.send_transfer(depth=2, transfers=[transaction])
        url = "https://thetangle.org/bundle/" + str(bundle["bundle"].hash)
        print url
        #.info(url)
        return str(iota_api.find_transactions([bundle["bundle"].hash])['hashes'][0])
    except iota.adapter.BadApiResponse as error:
        #logger.error(error)
        return False

def prepareTransaction(message=None, value=0):
    if message:
        message = iota.TryteString.from_string(message)
    tag = iota.Tag(b"SDPPBUYER")

    transaction = iota.ProposedTransaction(
        address=payment_address,
        value=value,
        message=message,
        tag=tag
    )

    return sendTransaction(transaction)


def receiveMenu():
    message = server.recv(2048)
    message = json.loads(message)

    data = json.loads(str(message['data']))

    #TODO - verify seller signature

    return iota.Address(str(data['payment-address'])), str(data['payment-granularity']), data['menu']

def prepareOrderData(data_type, quantity, currency):
    data = {}

    data['data_type'] = data_type
    data['quantity'] = quantity
    data['currency'] = currency

    data['signature-key'] = signature_key.publickey().exportKey('OpenSSH')
    data['encryption-key'] = encrypt_key.publickey().exportKey('OpenSSH')

    data['address'] = invoice_address

    return data

def placeOrder(available_data):

    print "Data type: "
    data_type = sys.stdin.readline()

    # TODO validate user input
    '''
    while not validate_user_input(data_type, available_data):
        print "Please follow this format : <data_request> <quantity>\n"
        data_type = sys.stdin.readline()
    '''

    print "Quantity: "
    quantity = sys.stdin.readline()

    print "Currency: "
    currency = sys.stdin.readline()

    buyer_order = str(data_type)+ ' ' + str(quantity)

    # Sign the order
    signature = str(signData(signature_key, buyer_order))

    # Generate a tangle address and push signed order to tangle
    transaction_hash = prepareTransaction(message=buyer_order + ' ' + signature)

    print transaction_hash

    data = prepareOrderData(data_type, quantity, currency)

    json_string = prepareJSONstring("ORDER", json.dumps(data), signature, transaction_hash)

    server.send(json_string)

    return quantity


def dataTransferInfo():
    message = server.recv(2048)
    message = json.loads(message)
    #pprint.pprint(message)

    k = key.decrypt(ast.literal_eval(message['data']))
    money_addr = message['tangle_info']

    return int(k), money_addr

def sendIotas(money_addr, val, iotas):
    return prepareTransaction(money_addr, value=val*iotas, message = "")

def dataTransfer(quantity, k, money_addr, data_request, iotas):
    counter = 1
    filename = data_request + ".txt"
    f = open(filename, "a")
    last_counter=0
    new_money_addr = ""

    while counter <= quantity:
        message = server.recv(2048)
        message = json.loads(message)
        #pprint.pprint(message)

        if counter%k == 0:
            new_money_addr = message['tangle_info']

        sensor_data = key.decrypt(ast.literal_eval(message['data']))
        f.write(sensor_data+'\n')

        if counter == quantity:
             print counter-last_counter
             addr = sendIotas(money_addr, counter-last_counter, iotas)
             json_string = prepareJSONstring(ack=1, tangle_info=addr, signature=signData(key, "1"))
             server.send(json_string)
             break

        if counter % k == 0:
            print k
            addr = sendIotas(money_addr, k, iotas)
            json_string = prepareJSONstring(ack=1, tangle_info=addr, signature=signData(key, "1"))
            last_counter = counter
        else:
            json_string = prepareJSONstring(ack=1, signature=signData(key, "1"))

        server.send(json_string)
        if new_money_addr != "":
            money_addr = new_money_addr
            new_money_addr = ""
        counter = counter + 1

# Usage
if len(sys.argv) != 3:
    print "Correct usage: script, IP address, port number"
    exit()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
IP_address = str(sys.argv[1])
Port = int(sys.argv[2])
server.connect((IP_address, Port))

# connect to IOTA server

# running on a light wallte node
seed = "RAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHULRAHUL9RAHUL"
client = "http://node02.iotatoken.nl:14265"
iota_api = iota.Iota(client, seed)
#logger = create_logger(severity=logging.DEBUG)
#iota_api.adapter.set_logger(logger)

# generate keys
encrypt_key = RSA.generate(2048)
signature_key = RSA.generate(2048, e=65537)

payment_address = ""

invoice_address = iota_api.get_new_addresses(count=1)
invoice_address = str(invoice_address['addresses'][0].address)


while True:

    payment_address, payment_granularity, available_data = receiveMenu()

    quantity = placeOrder(available_data)

    break

    print "Step 1 Success"
    k, money_addr = dataTransferInfo()
    print "Step 2 Success"
    dataTransfer(quantity, k, money_addr, data_request, iotas)
    print "Done!"
    break

server.close()
