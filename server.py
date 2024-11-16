from scapy.all import * 
from datetime import datetime
from colorama import Fore,Style
from random import choice
from functions import getPoolAddresses,givenArrayGetByString,mac_to_bytes
print("DHCP server v1.0")

dhcp_server_ip = "192.168.1.100"

#ip_selected = "192.168.1.24"
gateway = "192.168.1.254"
lease_time = 60*60*24
#lease_time = 15
half_lease_time = lease_time // 2
mask = "255.255.255.0"
dns = "8.8.8.8"
pool = getPoolAddresses("192.168.1.101","192.168.1.200",mask)

# pending: make a function, if it exceds the size by certain amount
# it starts to send deny dhcp requests
transactions = {}

def sendOffer(pkt):
    transaction_id = pkt[UDP][BOOTP].xid
    
    mac_source = pkt[Ether].src

    xid_hex = str(hex(transaction_id))

    try:
        transactions[xid_hex]
    except:
        transactions[xid_hex] = choice(pool) 

    ip_selected = transactions[xid_hex]

    print(Fore.RED+str(transactions)+Style.RESET_ALL)
    print(Fore.GREEN+xid_hex+Style.RESET_ALL)
    
    offer = Ether(dst=mac_source)/IP(dst=ip_selected)/UDP()/BOOTP(xid=transaction_id,yiaddr=ip_selected,siaddr=dhcp_server_ip,giaddr=gateway,chaddr=mac_to_bytes(mac_source),op=2,hops=1)/DHCP(options=[("message-type",2),("subnet_mask",mask),("router",gateway),("renewal_time",half_lease_time),("lease_time",lease_time),("name_server",dns),"end"])
    sendp(offer,verbose=0)



def fn(pkt):
    if pkt[UDP].sport in [68,67] or pkt[UDP].dport in [68,69]:
        try:
            pkt[DHCP]
            #offer
            #if the packet is a dhcp discovery
            if (pkt[DHCP].options[0][1] == 1) and pkt[UDP].sport== 68 and pkt[UDP].dport== 67:#is a discover packet
                sendOffer(pkt)
                pkt.show()
            #ack
            #if the packet is a dhcp request
            elif (pkt[DHCP].options[0][1] ==3) and pkt[UDP].sport== 68 and pkt[UDP].dport== 67:#is a request packet
                #save the transaction id
                #save the mac mac_source
                pkt.show()
                transaction_id = pkt[UDP][BOOTP].xid
                mac_source = pkt[Ether].src

                xid_hex = str(hex(transaction_id))
                
                print(Fore.YELLOW+str(transactions)+Style.RESET_ALL)
                print(Fore.GREEN+xid_hex+Style.RESET_ALL)

                host_name = givenArrayGetByString(pkt[DHCP].options,"hostname")
                try:
                    #sending the ack
                    transactions[xid_hex]
                    ack = Ether(dst=mac_source)/IP(dst=transactions[xid_hex])/UDP()/BOOTP(xid=transaction_id,yiaddr=transactions[xid_hex],siaddr="0.0.0.0",giaddr=gateway,chaddr=mac_to_bytes(mac_source),op=2,hops=1)/DHCP(options=[("message-type",5),("subnet_mask",mask),("router",gateway),("renewal_time",half_lease_time),("lease_time",lease_time),("name_server",dns),"end"])
                    sendp(ack,verbose=0)
                    pool.remove(transactions[xid_hex])
                    print(len(pool))
                    print(Fore.YELLOW + host_name, Style.RESET_ALL + "[ACK]", Fore.GREEN + mac_source, Fore.BLUE  +transactions[xid_hex], Fore.CYAN + str(datetime.now()) + Style.RESET_ALL)
                except:
                    #user is trying to send a request with a xid, but that xid is not on db
                    #they are doing a dhcp request without doing a dhcp discovery
                    sendOffer(pkt)
                
        except Exception as e:
            ##pass
            print("err",hex(e))

sniff(prn=fn, store=0,filter="udp")
