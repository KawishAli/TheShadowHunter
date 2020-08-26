import nmap
import socket
import json
from pymongo import MongoClient

nmScan = nmap.PortScanner()
dic_maxdetail = {}


def network_discovery(ip):
    nmScan.scan(ip)
    for host in nmScan.all_hosts():
        ipv4 = nmScan[host]['addresses']['ipv4']
        dic_maxdetail.setdefault(ipv4, {})
        for proto in nmScan[host].all_protocols():
            temp = {}
            for port_key in sorted(nmScan[host][proto].keys()):
                temp1 = {}
                if 'name' in nmScan[host][proto][port_key]:
                    temp1['name'] = nmScan[host][proto][port_key]['name']
                if 'state' in nmScan[host][proto][port_key]:
                    temp1['state'] = nmScan[host][proto][port_key]['state']
                if 'product' in nmScan[host][proto][port_key]:
                    temp1['product'] = nmScan[host][proto][port_key]['product']
                if 'version' in nmScan[host][proto][port_key]:
                    temp1['version'] = nmScan[host][proto][port_key]['version']
                temp[port_key] = temp1
            dic_maxdetail[ipv4] = temp
    return dic_maxdetail


def json_Converter():
    jsonconverted = json.dumps(dic_maxdetail)
    return jsonconverted


def DatabaseInsertion(list_data):
    client = MongoClient('mongodb://182.180.96.204:27017')
    db = client['shadowhunters']
    col = db["scanners"]
    ids = col.insert_many(list_data)
    print(ids.inserted_ids)
    print("Data inserted successfully")
    client.close()


def data_suggestion():
    data_suggest = {}
    for values in dic_maxdetail.values():
        for value in values:
            if value in data_suggest:
                data_suggest[value] = data_suggest.get(value) + 1
            else:
                data_suggest.setdefault(value, 1)
    return data_suggest


def recieved_data():
    serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv.bind(('0.0.0.0', 8095))
    serv.listen(5)
    conn, addr = serv.accept()
    data = str(conn.recv(1000000), 'utf-8')
    conn.close()
    return data


def dataDenormalization(scanner_result):
    list_of_result = []
    print("-------------------------------------------")
    for IPaddress, ports in scanner_result.items():
        for port_number, port_detail in ports.items():
            # print(port_detail)
            tempdict = {"ip_address": IPaddress, "port": port_number, "name": port_detail["name"],
                        "state": port_detail["state"],
                        "product": port_detail["product"], "version": port_detail["version"]}
            # print(IPaddress, ports)
            list_of_result.append(tempdict)
    return list_of_result


print("The Scanner Successfully Started")
ipaddress = recieved_data()
print("The network " + ipaddress + " is about to scan")
print("The Scan is started.................")
full_data = network_discovery(ipaddress)
suggest_data = data_suggestion()
list_of_data = dataDenormalization(full_data)
print(list_of_data)
DatabaseInsertion(list_of_data)
print("The Scan is successfully completed")

# data_in_json  = json_Converter()
# print(data_in_json)
