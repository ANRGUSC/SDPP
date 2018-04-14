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

def prepareTransaction(addr="", value=0, message=""):
    if message != "":
        message = iota.TryteString.from_string(message)
    tag = iota.Tag(b"SDPPBUYER")

    if addr == "":
        addr = iota_api.get_new_addresses(count=1)
        addr  = addr['addresses'][0].address


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
    print transaction_hash

    return transaction_hash

def placeOrder():
    message = server.recv(2048)
    message = json.loads(message)
    print message['data']
    available_data = json.loads(message['data'].split("\n\n")[1])

    buyer_order = sys.stdin.readline()
    buyer_order = buyer_order.strip()

    while not validate_user_input(buyer_order, available_data):
        print "Please follow this format : <data_request> <quantity>\n"
        buyer_order = sys.stdin.readline()

    # Sign the order
    signature = signData(key, buyer_order)

    # Generate a tangle address and push signed order to tangle
    transaction_hash = prepareTransaction(message=buyer_order + '\n' + ''.join(str(signature)))

    if not transaction_hash:
        # send bad signal to server
        exit(0)

    json_string = prepareJSONstring(data=buyer_order, key=key.publickey().exportKey('OpenSSH'),
                                    tangle_info=transaction_hash, signature=signature)

    server.send(json_string)
    buyer_order = buyer_order.split(" ")
    return int(buyer_order[1]), buyer_order[0], int(available_data[buyer_order[0]].split(" ")[0])

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
seed = ""
client = "http://node02.iotatoken.nl:14265"
iota_api = iota.Iota(client, seed)
#logger = create_logger(severity=logging.DEBUG)
#iota_api.adapter.set_logger(logger)

# generate keys
key = RSA.generate(2048)

while True:

    quantity, data_request, iotas = placeOrder()
    print "Step 1 Success"
    k, money_addr = dataTransferInfo()
    print "Step 2 Success"
    dataTransfer(quantity, k, money_addr, data_request, iotas)
    print "Done!"
    break

server.close()
