###########################################################
#Thank you Aleksa Tamburkovski for providing the tutorial #
#Link to tutorial: youtube.com/watch?v=0NQ2aMxBYNE        #
###########################################################
import socket
from IPy import IP

########################################################################
#After the conversion takes place, we will scan for 100 ports using the#
#scan_port function                                                    #
########################################################################
def scan(target):
    converted_ip = check_ip(target)
    print("\n" + "[Scanning Target..." + str(target) + "]")
    for port in range(1, 100):
        scan_port(converted_ip, port)

#############################################################################
#If the target is an IP address, store it in converted_ip, otherwise perform#
#perfrom the socket.gethostbyname method to convert the domain name to an IP#
#address and store it in converted_ip                                       #
#############################################################################
def check_ip(ip):
    try:
        IP(ip)
        return(ip)
    except ValueError:
        return socket.gethostbyname(ip)

#####################################################################
#This function returns the banner if present using the s.recv method#
#####################################################################
def get_banner(s):
    return s.recv(1024)

################################################################################
#Create a socket object, set a timeout for speedy results, the connect function#
#is performed on the ipaddress and port number. If a banner is present it will #
#print with the open port number, otherwise only the open port will be printed.#
################################################################################
def scan_port(ipaddress, port):
    try:
        sock = socket.socket()
        sock.settimeout(0.5)
        sock.connect((ipaddress, port))
        try:
            banner = get_banner(sock)
            print('[+] Open Port ' + str(port) + ' : ' + str(banner.decode().strip('\n')))
        except:
            print('[+] Open Port ' + str(port))
    except:
        pass

#########################################################################################
#Ask user for input                                                                     #
#Check if the user inputted several targets, split each target, and scan each IP address#
#If user inputs one target, scan that one target                                        #
#########################################################################################
targets = input("Enter target(s) (IP Address/Domain) to scan(separate with ,): ")
if "," in targets:
    for ip_add in targets.split(","):
        scan(ip_add.strip(" "))
else:
    scan(targets)


