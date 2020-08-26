# -*- coding: utf-8 -*-

# !flask/bin/python
import time

from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
import pexpect
import yaml
import uuid
import ast
import sys
import os
import re
import socket
import pymongo
import json
from randmac import RandMac

add_department_scripts = ["openvpn.yml", "makeONETdirectory.yml", "transfer.yml", "vpn.yml", "onetinterface.yml",
                          "onet.yml", "dnet1.yml", "tunnel.yml", "onet_ofctl.yml", "wirelessInterface.yml",
                          "vxlanInterface.yml", "onetMAC.yml"]
script_inventory = "/home/kawish/vagrant_multi_edureka/"
output = []
counter = 0
Controller_IP = DNET_IP =  "192.168.18.39"

interface_name = []

app = Flask(__name__)
CORS(app, support_credentials=True)


@cross_origin(supports_credentials=True)
# @app.route('/todo/api/v1.0/tasks', methods=['GET'])
# def get_tasks():
#     return jsonify({'tasks': tasks})

@app.route('/add-department', methods=['POST'])
def add_department():
    database_list = {}
    global counter
    interface_name.clear()
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    database_list["account"] = username
    database_list["onet_dep_ip"] = ipaddress
    print(ipaddress)
    print(username)
    print(password)
    with open("/etc/ansible/hosts", "a+", encoding="utf-8") as myfile:
        myfile.write(
            username + " " + "ansible_host=" + ipaddress + " ansible_port=22 " + "ansible_user=" + username + " ansible_password=" + password + " ansible_sudo_pass=" + password + "\n")

    for item in add_department_scripts:
        if (item == "dnet1.yml"):
            ansible_script = read_file(script_inventory + item)
            for tags in ansible_script:
                if tags["tasks"][0]["command"] == "ovs-vsctl add-br br47":
                    tags["tasks"][0]["command"] = "ovs-vsctl add-br br" + str(counter)
                if tags["tasks"][2][
                    "command"] == "ovs-vsctl add-port br47 vxlan0":
                    tags["tasks"][2][
                        "command"] = "ovs-vsctl add-port br" + str(counter) + " vxlan" + str(
                        counter) + " -- set interface vxlan" + str(
                        counter) + " type=vxlan option=remote_ip=10.8.0." + str(counter + 2)
                if tags["tasks"][4]["command"] == "ip tuntap add mode tap tap0":
                    tags["tasks"][4]["command"] = "ip tuntap add mode tap tap" + str(counter)
                    database_list["dnet_tap_interface"] = "tap" + str(counter)
                if tags["tasks"][6]["command"] == "ifconfig tap0 up":
                    tags["tasks"][6]["command"] = "ifconfig tap" + str(counter) + " up"
                if tags["tasks"][8]["command"] == "ovs-vsctl add-port br47 tap0":
                    tags["tasks"][8]["command"] = "ovs-vsctl add-port br" + str(counter) + " tap" + str(counter)
            new_script_path = write_file(script_inventory + item, ansible_script)
            execute_ansible_script(new_script_path, item)
            delete_file(new_script_path)
            dnet_br0 = execute_interface_script(script_inventory + "dnet_ofctl.yml", "dnet_ofctl.yml")
            database_list["dnet_bridge"] = dnet_br0
            counter = counter + 1
        else:
            ansible_script = read_file(script_inventory + item)
            edited_script = scripts_necessary_changes_dept(ansible_script, item, username)
            new_script_path = write_file(script_inventory + item, edited_script)
            if item == "onetinterface.yml":
                interface = execute_interface_script(new_script_path, item)
                interface_name.append(interface)
            elif item == "onet_ofctl.yml":
                dpid = execute_interface_script(new_script_path, item)
                database_list["onet_dpid"] = dpid
            elif item == "vxlanInterface.yml":
                vxlan_interface = execute_interface_script(new_script_path, item)
                database_list["onet_vxlan_port_num"] = vxlan_interface
            elif item == "wirelessInterface.yml":
                wireless_interface = execute_interface_script(new_script_path, item)
                database_list["onet_wireless_port_num"] = wireless_interface
            elif item == "onetMAC.yml":
                onet_mac = execute_interface_script(new_script_path, item)
                database_list["onet_mac"] = onet_mac
            else:
                execute_ansible_script(new_script_path, item)
            delete_file(new_script_path)
    accessing_database("developments", database_list)
    database_list.clear()
    if "openvpn.yml" in add_department_scripts:
        index = add_department_scripts.index("openvpn.yml")
        add_department_scripts[index] = "openvpn2.yml"
    else:
        print("openvpn is already removed")
    return jsonify(True)


def scripts_necessary_changes_dept(script_path, item, username):
    if item == "onetinterface.yml" or item == "tunnel.yml" or item == "vxlanInterface.yml" or item == "onet_ofctl.yml" or item == "onetMAC.yml":
        script_path[0]["hosts"] = username
        return script_path
    elif item == "vpn.yml":
        if counter == 0:
            script_path[0]["vars"]["vpn_name"] = "client"
        else:
            script_path[0]["vars"]["vpn_name"] = "client" + str(counter)
        script_path[0]["hosts"] = username
        script_path[0]["vars"]["username"] = username
        return script_path
    elif item == "onet.yml":
        script_path[0]["vars"]["interface"] = interface_name[0]
        script_path[0]["hosts"] = username
        script_path[0]["vars"]["controller_ip"] = Controller_IP
        return script_path
    elif item == "transfer.yml":
        if counter == 0:
            script_path[0]["vars"]["vpn_name"] = "client"
            script_path[1]["vars"]["vpn_name"] = "client"
            script_path[1]["vars"]["username"] = username
        else:
            script_path[0]["vars"]["vpn_name"] = "client" + str(counter)
            script_path[1]["vars"]["vpn_name"] = "client" + str(counter)
            script_path[1]["vars"]["username"] = username
        script_path[1]["hosts"] = username
        return script_path
    elif item == "openvpn.yml":
        script_path[0]["vars"]["IP"] = DNET_IP
        return script_path
    elif item == "wirelessInterface.yml":
        script_path[0]["vars"]["Interface"] = interface_name[0]
        script_path[0]["hosts"] = username
        return script_path
    elif item == "makeONETdirectory.yml":
        script_path[0]["vars"]["username"] = username
        script_path[0]["hosts"] = username
        return script_path
    elif item == "openvpn2.yml":
        script_path[0]["vars"]["clientname"] = "client" + str(counter)
        return script_path


def execute_interface_script(script, item):
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8', timeout=60)
    result = child.read()
    if item == "onetinterface.yml":
        return re.search('(\B"msg":\W*")(\w*).*?\s', result).group(2)
    elif item == "onet_ofctl.yml" or item == "dnet_ofctl.yml":
        return re.search('dpid:?(\w*)', result).group(1)
    elif item == "vxlanInterface.yml" or item == "wirelessInterface.yml":
        return re.search('"msg":\W*(\d*)', result).group(1)
    elif item == "onetMAC.yml":
        return re.search('LOCAL(.*)(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)', result).group(2)


def execute_ansible_script(script, item):
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8', timeout=60)
    # child.expect(timeout=60)
    result = child.interact()
    child.close()
    # ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    # out = ansi_escape.sub('', out)
    # print(out)
    # output.append(out)


def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
    else:
        print("The file does not exist")


def read_file(file_path):
    yml = yaml
    with open(file_path) as yml_file:
        return yml.load(yml_file)


def write_file(file_path, script):
    yml = yaml
    output_file_path = file_path + str(uuid.uuid1()) + ".yml"
    with open(output_file_path, 'w+') as yml_file:
        yml.dump(script, yml_file)
    return output_file_path


@app.route('/getStatus', methods=['POST'])
def get_json():
    print("In get status method")
    req = request.json
    service = req["User_data"]["service"]
    ipaddress = req["User_data"]["IPaddress"]
    account = req["User_data"]["account"]
    if service == "SSH":
        item = "sshstatus.yml"
    elif service == "HTTP":
        item = "httpstatus.yml"
    elif service == "MYSQL":
        item = "mysqlstatus.yml"
    else:
        print("Wrong service selected")
        return
    ansible_script = read_file(script_inventory + item)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item, account)
    new_script_path = write_file(script_inventory + item, edited_script)
    output = execute_VM_scripts(new_script_path, item)
    print("The status has been shown")
    print("ONET VM " + service + " " + output[0][1].strip())
    print("DNET VM " + service + " " + output[1][1].strip())
    delete_file(new_script_path)
    return jsonify(output)

def execute_VM_scripts(script, item):
    print(item)
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8',
                          timeout=6000)
    # child.expect(timeout=60)
    # child.interact()
    output = child.read()
    child.close()
    if item == "sshstatus.yml" or item == "httpstatus.yml" or item == "mysqlstatus.yml":
        interface = re.findall('(default\s)(.*)(\(virtualbox)', output)
        return interface
    if item == "onetssh.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    elif item == "onethttp.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    elif item == "onetmysql.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    output = ansi_escape.sub('', output)
    print(output)
    return output


def scripts_necessary_changes_VM_onet(script, item, username):
    script[0]["vars"]["username"] = username
    script[0]["hosts"] = username
    return script


def scripts_necessary_changes_VM_dnet(script, item, ipaddress, interface , mac_address):
    script[0]["vars"]["interface"] = interface
    script[0]["vars"]["IPaddress"] = ipaddress
    script[0]["vars"]["macAddress"] = mac_address
    return script

def get_tap_interface_name(query):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    mycol = mydb["developments"]
    for x in mycol.find(query):
        interface = x["dnet_tap_interface"]
        myclient.close()
        return interface
    myclient.close()

def notifiedController(query):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((Controller_IP, 8090))
    client.sendall(query.encode())
    client.close()

@app.route('/execute-VM', methods=['POST'])
def ansible1():
    output_array = []
    database_list = {}
    req = request.json
    # req = request.values.values()
    service_name = req["User_data"]["service"]
    username = req["User_data"]["account"]
    database_list["account"] = username
    database_list["service"] = service_name
    query = {"account": username}
    notified_query = {"account": username , "service" : service_name}
    json_query = json.dumps(notified_query)
    if service_name == "SSH":
        item_onet = "onetssh.yml"
        item_dnet = "dnetssh.yml"
    elif service_name == "HTTP":
        item_onet = "onethttp.yml"
        item_dnet = "dnethttp.yml"
    elif service_name == "MYSQL":
        item_onet = "onetmysql.yml"
        item_dnet = "dnetmysql.yml"
    else:
        print("Wrong service selected")
        return
    ansible_script = read_file(script_inventory + item_onet)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item_onet, username)
    new_script_path = write_file(script_inventory + item_onet, edited_script)
    ipaddress = execute_VM_scripts(new_script_path, item_onet)
    database_list["onet_VM_ip"] = ipaddress
    delete_file(new_script_path)
    tuntap = get_tap_interface_name(query)
    MAC = RandMac("080027000000")
    database_list["dnet_VM_mac"] = MAC.mac
    ansible_script = read_file(script_inventory + item_dnet)
    edited_script = scripts_necessary_changes_VM_dnet(ansible_script, item_dnet, ipaddress, tuntap , MAC.mac)
    new_script_path = write_file(script_inventory + item_dnet, edited_script)
    VM_result = execute_VM_scripts(new_script_path, item_dnet)
    delete_file(new_script_path)
    accessing_database("VMdetails" , database_list)
    database_list.clear()
    output_array.append(VM_result)
    print("above notified")
    notifiedController(json_query)
    print("below notified")
    notified_query.clear()
    query.clear()
    return jsonify(output_array)

@app.route('/Delete-VM', methods=['POST'])
def ansible3():
    output_array = []
    req = request.json
    service = req["User_data"]["service"]
    ipaddress = req["User_data"]["IPaddress"]
    account = req["User_data"]["account"]
    if service == "SSH":
        item = "sshhalt.yml"
    elif service == "HTTP":
        item = "httphalt.yml"
    elif service == "MYSQL":
        item = "mysqlhalt.yml"
    else:
        print("Wrong service selected")
        return
    ansible_script = read_file(script_inventory + item)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item, account)
    new_script_path = write_file(script_inventory + item, edited_script)
    output = execute_VM_scripts(new_script_path, item)
    query = {"account": account , "service":service}
    deleting_data_from_database(query)
    delete_file(new_script_path)
    print("VM's are halt and database is deleted")
    return jsonify(output)

@app.route('/ReloadVM', methods=['POST'])
def ansible2():
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    service = req["User_data"]["service"]
    print(ipaddress)
    print(username)
    print(password)
    if service == "SSH":
        item = "sshReload.yml"
    elif service == "HTTP":
        item = "httpReload.yml"
    elif service == "MYSQL":
        item = "mysqlReload.yml"
    else:
        print("Wrong service selected")
        return
    ansible_script = read_file(script_inventory + item)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item, username)
    new_script_path = write_file(script_inventory + item, edited_script)
    output = execute_VM_scripts(new_script_path, item)
    delete_file(new_script_path)
    print("The VM's are Reloaded")
    return jsonify(output)

@app.route('/DestroyVM', methods=['POST'])
def ansible4():
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    service = req["User_data"]["service"]
    print(ipaddress)
    print(username)
    print(password)
    if service == "SSH":
        item = "sshDestroy.yml"
    elif service == "HTTP":
        item = "httpDestroy.yml"
    elif service == "MYSQL":
        item = "mysqlDestroy.yml"
    else:
        print("Wrong service selected")
        return
    ansible_script = read_file(script_inventory + item)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item, username)
    new_script_path = write_file(script_inventory + item, edited_script)
    output = execute_VM_scripts(new_script_path, item)
    delete_file(new_script_path)
    print("The onet VM's are destroyed")
    return jsonify(output)

@app.route('/Delete-Dept', methods=['POST'])
def ansible5():
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    print(ipaddress)
    print(username)
    print(password)
    item = "deleteDept.yml"
    ansible_script = read_file(script_inventory + item)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item, username)
    new_script_path = write_file(script_inventory + item, edited_script)
    output = execute_VM_scripts(new_script_path, item)
    delete_file(new_script_path)
    query = {"account": username}
    deleting_data_from_database_dept(query)
    print("The Departments are deleted")
    return jsonify(output)

@app.route('/execute-scanner', methods=['POST'])
def scanner():
    req1 = request.json
    req = request.values.values()
    ipaddress = req1["User_data"]["IPaddress"]
    # print(dict_req["User_data"])
    print("In the scanner method")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.18.39', 8095))
    client.sendall(ipaddress.encode())
    client.close()
    return jsonify("IP address recieved")

def accessing_database(collection_name, mylist):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    if collection_name == "developments":
        mycol = mydb["developments"]
        data = mycol.insert_one(mylist)
        print(data)
    if collection_name == "VMdetails":
        mycol = mydb["VMdetails"]
        data = mycol.insert_one(mylist)
        print(data)
    print(mylist)
    myclient.close()

def deleting_data_from_database(query):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    mycol = mydb["VMdetails"]
    mycol.delete_one(query)

def deleting_data_from_database_dept(query):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    mycol = mydb["developments"]
    mycol.delete_one(query)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)