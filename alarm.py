#!/usr/bin/python


########################################
#                                      # 
# Allie Clifford                       # 
# Comp 116 Security Lab 6              # 
# Network Alarm Sniffer                # 
# Date created: 7/24/2017              #                    
#                                      # 
# Added some sql injection detection   #
# on 1/7/2019                          #
#                                      # 
########################################


from scapy.all import *
import pcapy
import argparse
import re
import base64

inc_count = 0

def add_inc(): 
    global inc_count
    inc_count +=1

def store_username(usernames, arg):
    usernames.append(arg)

def clear_usernames(usernames):
    usernames = []

def alert_i(arg1, arg2, arg3, arg4):
    add_inc()
    print "ALERT #{}: {} is detected from {} ({}) ({})".\
format(inc_count, arg1, arg2, arg3, arg4)


def alert_r(arg_1, arg_2):
    add_inc()
    print "ALERT #{}: Usernames and passwords sent in-the-clear({})({})".\
format(inc_count, arg_1, arg_2)


#check for usernames and passwords sent in the clear
#checks for flags from common malicious scanning activities
#checks for possible sql injection attacks
#checks for possible cross-site scripting attack
def packetcallback(packet): 
    sent_usernames = []
    pkt_cpy_inj = copy.deepcopy(packet)
    pkt_cpy_flags = copy.deepcopy(packet)
    pkt_cpy_pw = copy.deepcopy(packet)
    try:
        check_inj(pkt_cpy_inj)
        check_usernames(sent_usernames, pkt_cpy_pw)
        check_flags(pkt_cpy_flags)
    except IOError as e:
        print("IOError: ", e) 
        pass
    except StandardError as e:
        #print("Generic error occurred: ", e)
       # print(packet)
        pass

#check for common commands used in sqlinjection and cross site scripting attack
#uses a small set of known sqlinjection commonds converted into regular 
#expressions for ease of searching within the raw data
def check_inj(packet):
    
    #print("i probably need a try statement here huh")
    drop = "drop"
  #  uscript = "<script>"
    escript = "%3Cscript%eE" 
    ESCRIPT = "%3CSCRIPT%eE"
    
    DROP = "DROP"
    USCRIPT = "SCRIPT"
    uscript = "script"
    
    one_one = "1=1"
    one_apos = "'1'='1"
    one_two = "1=2"
    two_apos = "'1'='2"
    dele = "delete"  
    DEL = "DELETE"
    vers = "substring(@@version)"

    try:
        pkt_decode = str(packet[Raw]).encode("ASCII")
        pkt_decode = str(pw_check)
        if(re.search(drop, pkt_decode) or re.search(DROP, pkt_decode) \
        or re.search(vers, pkt_decode) or re.search(one_one, pkt_decode) \
        or re.search(one_apos, pkt_decode) or re.search(two_apos, pkt_decode) \
        or re.search(dele, pkt_decode) or re.search(DEL, pkt_decode)): 
            alarm = "POSSIBLE SQL INJECTION DETECTED!"
            alert_i(alarm, packet[IP].src, packet[TCP].dport, packet[Raw], inc_count) 
            log_pkt(alarm, packet)
        elif(re.search(ESCRIPT, pkt_decode) or re.search(escript, pkt_decode) or \
        re.search(USCRIPT, pkt_decode) or re.search(uscript, pkt_decode)):
            alarm = "POSSIBLE CSSI DETECTED"
            alert_i(alarm, packet[IP].src, packet[TCP].dport, packet[Raw], inc_count)
            log_pkt(alarm, packet)
    except: 
        pass
 
#check for clear text usernames/passwords
def check_usernames(sent_usernames, packet):
    port_ch = 0

    alarm = "clear text credentials"
    pw_check = str(packet[Raw]).encode("ASCII")
    pw_check = str(pw_check)

    pw_keywords = ["PASS+", "pass+", "PASS=", "pass=","pw", "PW","&pass",
"&PASS"]
    http_log = re.search('42 LOGIN', pw_check)
    IMAP_log = re.search('LOGIN+', pw_check)
    usernames = re.search('USER+', pw_check)
    #http port
    if packet[TCP].dport == 80:
        print "Warning: Unencrypted HTTP (web) traffic detected!"
        port_ch = 80 

    #IMAP port
    elif packet[TCP].dport == 143:
        port_ch = 143
    #common FTP port
    elif packet[TCP].dport == 53605:
        port_ch = 53605
    #pop3 port
    elif packet[TCP].dport == 110:
        port_ch = 110
    #common SMTP and SMTP AUTH ports
    elif packet[TCP].dport == 25 or packet[TCP].dport == 2525 \
         or packet[TCP].dport == 587:
        port_ch = packet[TCP].dport
        #telnet and FTP port
    elif packet[TCP].dport == 23 or packet[TCP].dport == 21:
        port_ch = packet[TCP].dport
    try:
        if port_ch == 80 or packet[TCP].dport == 443:
            
            b64_check = str(packet[Raw])
            base64.b64decode(b64_check)
            get_req = re.search('GET+', b64_check)
            if get_req:
                to_decode = re.search('.*Authorization: Basic (.*)==.*', b64_check)
                if to_decode:
                    user = to_decode.group(1)
                    user = user + '=='
                    user = base64.b64decode(user)
                    alert_r(port_ch, user)                
                    log_pkt(alarm, packet)
            flag = 0
            post_check = str(packet[Raw]).split()
            for word in range(len(post_check)):
                for keyword in pw_keywords: 
                        if re.search(keyword, post_check[word]):
                            nuser = post_check[word]
                            alert_r(port_ch, nuser)
                            log_pkt(alarm, packet)
                            break
        if usernames and port_ch != 80:
            store_username(sent_usernames, pw_check)
        #if passwords and port_ch != 80:
        #    store_username(sent_usernames, pw_check)
        #    alert_r(port_ch, username, inc_count)
        #    log_pkt(alarm, packet)
        #    clear_usernames(sent_usernames)
        if http_log or IMAP_log:
            if port_ch == 143:
                store_username(sent_usernames, pw_check)
                alert_r(port_ch, pw_check)
                clear_usernames(sent_usernames)
            #    alarm.append(pw_check)
                log_pkt(alarm, packet)
    except StandardError as e:
        print("Error parsing: ", e)
        pass
    except:
        pass

def log_pkt(alarm, packet):
    print("to write: packet logger!")

#check packet flags for signs of scans
#checking for null, fin, and xmas flags
def check_flags(packet, inc_count):
    FNULL = 0b00000000
    FFIN = 0b00000001
    FXMAS = 0b00101001
    try:
        flags = packet.sprintf('%TCP.flags%') 
        if flags == FNULL:
            alarm = "NULL"
            alert_i(alarm, packet[IP].src, packet[TCP].dport, packet[Raw], inc_count)
        elif flags == FFIN:
            alarm = "FIN"
            alert_i(alarm, packet[IP].src, packet[TCP].dport, packet[Raw], inc_count)
        elif flags == FXMAS:
            alarm = "XMAS"
            alert_i(alarm, packet[IP].src, packet[TCP].dport, packet[Raw], inc_count)
        else:
            pass
    except IOError as e:
        print("IOError parsing: ", e)
        print(flags)
        pass
    except StandardError as e:
        print("StandardError parsing: ", e)
        pass
    except:
        print("Unidentified Error parsing: ", e)
        pass

#parse command line args if any supplied
def parse():
    parser = argparse.ArgumentParser(description='A network sniffer that\
 identifies basic vulnerabilities')
    parser.add_argument('-i', dest='interface', help='Network interface \
to sniff on', default='eth0')
    parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
    args = parser.parse_args()
    return args

#run the user-supplied functionality, default is eth0 (no supplied user args)
def run_sniffer(eth0, args):
    if eth0:   
        try:
            print "Sniffing on default interface eth0... "  
            sniff(iface=eth0, prn=packetcallback)      
        except pcapy.PcapError:
            print "Sorry, error opening network interface eth0" 
        except:
            print "Sorry, can\'t read network traffic. Are you root?"
    elif args.pcapfile:
        try:
            print "Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile}
            sniff(offline=args.pcapfile, prn=packetcallback)
        except IOError:
            print("Sorry, something went wrong with the PCAP file %(filename)s \
IO!" % {"filename": args.pcapfile})
        except StandardError:
            print("Sorry, something went wrong with reading the PCAP file \
%(filename)s!" % {"filename": args.pcapfile})
    else:
        print "Sniffing on %(interface)s... " % {"interface" : args.interface}
        try:
            sniff(iface=args.interface, prn=packetcallback)
        except pcapy.PcapError:
            print "Sorry, error opening network interface %(interface)s. \
It does not exist." % {"interface" : args.interface}
        except:
            print "Sorry, can\'t read network traffic. Are you root?"

#main function-- parse any user-supplied args and run the sniffer
def main():
    try:
        if len(sys.argv) == 1:
            run_sniffer(1, sys.argv)
        elif len(sys.argv) == 3:
            args = parse()
            run_sniffer(0, args)
        else:
            print "useage: alarm.py [-h] [-i INTERFACE] [-r PCAPFILE]"
    except StandardError as e:
        print("error: ", e)
    except:
        print("something else broke")

main()
