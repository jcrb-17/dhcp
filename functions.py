from itertools import product
 
 
#given decimal number return binary octet
def toBinary(decimal) -> str:
    binary = str(bin(decimal)).replace("0b","")
    if len(binary) != 8:
        string = "0"* (8 - len(binary))
        binary = string + binary
    #print(binary)
    return binary

#given a string in binary, return in decimal
def toDecimal(binary):
    #print(binary)
    return int(str(binary),2)

#returns the index to begin counting
def getMaskInNumber(mask_full_format):
    arr = mask_full_format.split(".")
    mask = ""
    for i in arr:
        mask += toBinary(int(i))
    #print(mask)
    count = 0
    for i in mask:
        if i == "1":
            count += 1
    #print(count)
    return count

def givenIpBinaryGetInDecimal(binaryAddr) -> str:
    octet1 = toDecimal(int(binaryAddr[:8]))
    octet2 = toDecimal(int(binaryAddr[8:16]))
    octet3 = toDecimal(int(binaryAddr[16:24]))
    octet4 = toDecimal(int(binaryAddr[24:32]))
    #print("{}.{}.{}.{}".format(octet1,octet2,octet3,octet4))
    return("{}.{}.{}.{}".format(octet1,octet2,octet3,octet4))
     
#addresses that are available for being assigned
def getPoolAddresses(fromAddr1,toAddr2,mask):
    addrfrom = fromAddr1.split(".")
    stringbinaryfrom = ""
    for i in addrfrom:
        stringbinaryfrom += toBinary(int(i))
    mask_count = getMaskInNumber(mask)
    
    #the from address, but only the submask section
    stringbinaryfrom = stringbinaryfrom[0:mask_count]

    perm = product(["0", "1"],repeat=32-mask_count) 
    
    pool = []
    started = False

    # Print the obtained permutations 
    for i in list(perm):
        aux = ""
        for j in i:
            aux += j
        #print(stringbinaryfrom+aux,len(stringbinaryfrom+aux))
        temp = givenIpBinaryGetInDecimal(stringbinaryfrom+aux)
        if temp == fromAddr1:
            pool.append(temp)
            started = True
        else:
            if started == True:
                if temp == toAddr2:
                    pool.append(temp)
                    return pool
                else:
                    pool.append(temp)

#to return the hostname, in dhcp options
def givenArrayGetByString(arr,string):
    for i in arr:
        if i[0] == string:
            return i[1].decode("utf-8")
    return None

def mac_to_bytes(mac_addr: str) -> bytes:
    """ Converts a MAC address string to bytes.
    """
    return int(mac_addr.replace(":", ""), 16).to_bytes(6, "big")


#getMaskInNumber("255.255.252.0")
#pool = getPoolAddresses("192.168.1.2","192.168.1.10","255.255.255.0")

#print(pool)
