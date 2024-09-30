import random
import socket
import struct
import sys

#################### Build Query Message ####################

print("Preparing DNS query..")

#generate random 16 bits for id
id = random.randint(0, 65000)

# recursion bit set to 1
flags = 0x0100

# qdcount set to 1 and all else set to 0
qdcount = 0x0001
ancount = 0x0000
nscount = 0x0000
arcount = 0x0000

# query header
header = struct.pack(">HHHHHH", id, flags, qdcount, ancount, nscount, arcount)

# split the url up and convert into labels
url = sys.argv[1]
question = b''
for section in url.split('.'):
    question += struct.pack('B', len(section)) + section.encode('utf-8')
question += b'\x00'
 
# QTYPE set to 1 for A type records
question += b'\x00\x01'

#QCLASS set to 1 for internet
question += b'\x00\x01'

# final query
query = header + question

#################### Send Query Message ####################

print("Contacting DNS server..")

# Google public DNS server
servAddr = '8.8.8.8'
portno = 53

# Create UDP socket and set timeout to 5 seconds
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send query request
attempts = 1
while attempts <= 3:
    print(f"Sending DNS query..")
    try:
        sock.sendto(query, (servAddr, portno))
        sock.settimeout(5)

        # recieve response message
        response, _ = sock.recvfrom(2048)
        print(f"DNS response received (attempt {attempts} of 3)")
        break
    
    except socket.timeout:
        attempts += 1
        if attempts == 3:
            print("Error: Query timed out after 3 attempts")

#################### Process Query Message ####################

print("Processing DNS response..\n")
print("-----------------------------------------------------------------\n")

# header ID
print(f"header.ID = 0x{response[:2].hex()}")

# header QR
print(f"header.QR = {response[2] >> 7}")

# header OPCODE
print(f"header.OPCODE = {(response[2] >> 3) & 15}")

# header AA
print(f"header.AA = {(response[2] >> 2) & 1}")

# header TC
print(f"header.TC = {(response[2] >> 1) & 1}")

# header RD
print(f"header.RD = {response[2] & 1}")

# header RA
print(f"header.RA = {(response[3] >> 7)}")

# header Z
print(f"header.Z = {(response[3] >> 4) & 7}")

# header RCODE
print(f"header.RCODE = {response[3] & 15}")

# header QDCOUNT
print(f"header.QDCOUNT = {int.from_bytes(response[4:6], "big")}")

# header ANCOUNT
numAnswers = int.from_bytes(response[6:8], "big")
print(f"header.ANCOUNT = {numAnswers}")

# header NSCOUNT
print(f"header.NSCOUNT = {int.from_bytes(response[8:10], "big")}")

# header ARCOUNT
print(f"header.ARCOUNT = {int.from_bytes(response[10:12], "big")}\n")

# question QNAME
cursor = 12
while response[cursor] != 0:
    cursor += 1

print(f"question.QNAME = 0x{response[12:cursor+1].hex()}")

# question QTYPE
print(f"question.QTYPE = {int.from_bytes(response[cursor+1:cursor+3], "big")}")

# question QClASS
print(f"question.QCLASS = {int.from_bytes(response[cursor+3:cursor+5], "big")}\n")

# answer RRs
cursor += 5
for i in range(numAnswers):
    # answer NAME
    print(f"answer.NAME = 0x{response[cursor:cursor+2].hex()}")

    # answer TYPE
    print(f"answer.TYPE = 0x{response[cursor+2:cursor+4].hex()}")

    # answer CLASS
    print(f"answer.CLASS = 0x{response[cursor+4:cursor+6].hex()}")

    # answer TTL
    print(f"answer.TTL = {int.from_bytes(response[cursor+6:cursor+10])} seconds")

    # answer RDLENGTH
    dataLength = int.from_bytes(response[cursor+10:cursor+12])
    print(f"answer.RDLENGTH = {dataLength}")

    # answer RDATA
    cursor += 12
    dataStr = "answer.RDATA = "
    for i in range(dataLength):
        dataStr += f"{response[cursor+i]}"
        dataStr += "."
    print(dataStr[:-1])
    cursor += dataLength
    print()