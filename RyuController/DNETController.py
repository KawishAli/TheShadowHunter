import socket

import pymongo
from apt_pkg import init

import simple_switch_l3
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.ovs import bridge
from ryu.lib.ovs import vsctl
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import threading
import json


class Routing(simple_switch_l3.SimpleSwitch13):
    datapath_list = {}

    def __init__(self, *args, **kwargs):
        self.serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serv.bind(('0.0.0.0', 8090))
        threading.Thread(target=self.received_data).start()
        super().__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.mynaem = []
        datapath = ev.msg.datapath
        self.datapath_list.setdefault(hex(datapath.id)[2:], datapath)
        parser = datapath.ofproto_parser
        id = datapath.id
        super().switch_features_handler(ev)
        print("Basic rule is set")
        print(self.datapath_list)
        # match, action = self.NormalPacketRule(parser)
        # super().add_flow(datapath, 0, match, action)
        # print("Normal flow added")
        # self.PacketDrop(parser,datapath)

        services_list = [1, 6, 17]
        # for service in services_list:
        #     match, actions = self.PacketForwardingToDeception(parser, service)
        #     super().add_flow(datapath, 1, match, actions)
        #     print("Towards deception rule is set")
        #     match, actions = self.PacketForwardingToAttacker(parser, service)
        #     super().add_flow(datapath, 1, match, actions)
        #     print("Towards attacker rule is set")

    def received_data(self):
        self.serv.listen(5)
        while True:
            conn, addr = self.serv.accept()
            try:
                data = conn.recv(10000).decode()
                sender_query = json.loads(data)
                print(sender_query)
                self.set_rules_of_controller(sender_query)
            except KeyboardInterrupt:
                print("Closing connection")
                conn.close()
            except:
                print("In the except of received data")
                continue
            conn.close()

    def set_rules_of_controller(self, sender_query):
        account_name = sender_query["account"]
        print(account_name)
        service_name = sender_query["service"]
        print(self.datapath_list)
        services_list = [1, 6, 17]
        priority = 1

        print(type(sender_query))
        VMdetails_from_database = self.databaseAccesing("VMdetails", sender_query)
        print(VMdetails_from_database)
        developments_from_database = self.databaseAccesing("developments", {"account": account_name})
        print(developments_from_database)
        onet_dpid = developments_from_database["onet_dpid"]
        print(onet_dpid[4:])
        onet_wireless_port_num = developments_from_database["onet_wireless_port_num"]
        onet_vxlan_port_num = developments_from_database["onet_vxlan_port_num"]
        onet_mac = developments_from_database["onet_mac"]
        onet_VM_ip = VMdetails_from_database["onet_VM_ip"]
        dnet_VM_mac = VMdetails_from_database["dnet_VM_mac"]
        print("The cursor is here")
        if onet_dpid[4:] in self.datapath_list:
            onet_datapath = self.datapath_list.get(onet_dpid[4:])
            parser = onet_datapath.ofproto_parser
            for service in services_list:
                match, actions = self.PacketForwardingToDeception(parser, service, onet_mac, onet_VM_ip, dnet_VM_mac,
                                                                  onet_vxlan_port_num)
                super().send_flow_mod(onet_datapath, priority, match, actions)
                print("Towards deception rule is set for " + str(onet_dpid))

                match, actions = self.PacketForwardingToAttacker(parser, service, dnet_VM_mac, onet_VM_ip, onet_mac,
                                                                 onet_wireless_port_num)
                super().send_flow_mod(onet_datapath, priority, match, actions)
                print("Towards attacker rule is set for " + str(onet_dpid))
        else:
            onet_datapath = None
            print("No datapath found")



    def databaseAccesing(self, collection_name, query):
        myclient = pymongo.MongoClient("mongodb://192.168.18.6:27017/")
        mydb = myclient["shadowhunter-backend"]
        if collection_name == "developments":
            mycol = mydb["developments"]
        elif collection_name == "VMdetails":
            mycol = mydb["VMdetails"]
        else:
            mycol = None
            print("Wrong collection name")
            return
        for details in mycol.find(query):
            return details
        myclient.close()

    def PacketForwardingToDeception(self, parser, service, onet_mac, onet_VM_ip, dnet_VM_mac, onet_vxlan_port_num):
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=service, eth_dst=onet_mac,
                                ipv4_dst=onet_VM_ip)
        actions = [parser.OFPActionSetField(eth_dst=dnet_VM_mac),
                   parser.OFPActionSetField(ipv4_dst=onet_VM_ip),
                   parser.OFPActionOutput(int(onet_vxlan_port_num))]
        return match, actions

    def NormalPacketRule(self, parser):
        match = parser.OFPMatch()
        action = [parser.OFPActionOutput(ofproto_v1_3.OFPP_NORMAL, 0)]
        return match, action

    def PacketDrop(self, parser, datapath, priority=2, buffer_id=None):
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=6, eth_src="08:00:27:d9:fb:82")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS,
                                             [])]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def PacketForwardingToAttacker(self, parser, service, dnet_VM_mac, onet_VM_ip, onet_mac, onet_wireless_port_num):
        match = parser.OFPMatch(eth_type=0x0800, ip_proto=service, eth_src=dnet_VM_mac,
                                ipv4_src=onet_VM_ip)
        actions = [
            parser.OFPActionSetField(eth_src=onet_mac),
            # parser.OFPActionSetField(ipv4_src=onet_config["ip"]),
            parser.OFPActionOutput(int(onet_wireless_port_num))]
        return match, actions

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
