import socket
import sys
import whois
import dns.resolver
import shodan
import requests
import argparse


argparse = argparse.ArgumentParser(description="this is a basic info gatering tool",usage="python3 info_gathering.py -d DOMAIN [-s IP]")

argparse.add_argument("-d",'--domain',help="enter the domain name for footprinting")
argparse.add_argument("-s","--shodan",help="enter the ip for shodan search")

args = argparse.parse_args()
domain = args.domain
ip = args.shodan


print("[+] Domain {} and IP {}".format(domain,ip))


print(" ")
print("##############################################################################")
print("#########################  Getting WHOIS indo .....  #########################")
print(" ")
#------WHOIS PWD GATHERING-------------
try:
    py = whois.query(domain)
    print('Name : {}'.format(py.name))
    print('Creation_date : {}'.format(py.creation_date))
    print('Expiration_date : {}'.format(py.expiration_date))
    print('Registrar : {}'.format(py.registrar))
    print('Registrant : {}'.format(py.registrant))
    print('Registrant_country : {}'.format(py.registrant_country))
except:
    pass




#______implimmenting dns module
print(" ")
print("##############################################################################")
print("#########################  Getting DNS indo .....  ###########################")
print(" ")

try:
    for a in dns.resolver.resolve(domain,"A"):
        print("[+] A records: {}".format(a.to_text()))
    for ns in dns.resolver.resolve(domain, "NS"):
        print("[+] NS records: {}".format(ns.to_text()))
    for mx in dns.resolver.resolve(domain,"MX"):
        print("[+] MX records: {}".format(mx.to_text()))
    for txt in dns.resolver.resolve(domain, "TXT"):
        print("[+] TXT records: {}".format(txt.to_text()))
except:
    pass


print(" ")
print("##############################################################################")
print("######################  Getting GEOLOCATION indo .....  ######################")
print(" ")

try:
    response = requests.request('GET',"http://geolocation-db.com/json/" + socket.gethostbyname(domain)).json()
    print("[+] Contry : {}".format(response['country_name']))
    print("[+] Contry : {}".format(response['country_name']))
    print("[+] city : {}".format(response['city']))
    print("[+] latitude : {}".format(response['latitude']))
    print("[+] longitude : {}".format(response['longitude']))

except:
    pass


print(" ")
print("##############################################################################")
print("########################  Getting shodan indo .....  #########################")
print(" ")
if ip:
    try:
        api = shodan.Shodan("uDhitBqphbPmAlnchYNk3oepqb0Hoo2G")
        results = api.search(ip)
        print("[+] Results found : {}".format(results['total']))
        for result in results['matches']:
            print("[+] IP : {}".format(result['ip_str']))
            print("[+] DAA: {}".format(result['data']))
            print()
    except:
        print("[-] SHODAN ERROR")









