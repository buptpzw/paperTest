#!/usr/bin/env python
#coding:utf-8
__author__ = "muye"

from datetime import datetime

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4, ipv6, icmpv6
from ryu.lib import dpid as dpid_lib

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    DP1 = "0000888888888882" # 84 tplink
    DP2 = "0000888888888884" # 82 tplink
    DP3 = "0000888888888886" # 85 tplink
    MN = {
        "IP" : "fe80::9ad6:f7ff:fe94:1647",
        "MAC" : "98:d6:f7:94:16:47",
    }
    '''
    MN = {
        "IP" : "fe80::c607:2fff:fe17:c8e1",
        "MAC" : "c4:07:2f:17:c8:e1",
    }
    '''
    """
    MN = {
        "IP" : "fe80::4950:b4e7:5b57:e2a9",
        "MAC" : "88:25:93:01:b7:33",
    }    
    """
    CN = {
        "IP" : "fe80::3ca4:d2bc:c1ac:4728",
        "MAC" : "00:21:70:BB:22:05",
    }

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.LI_POOL = {
            self.DP1 : {self.MN["IP"] : "fe80::1268:3fff:fe82:8f5d"},
            self.DP2 : {self.MN["IP"] : "fe80::1268:3fff:fe82:8f5c"},
#            self.DP1 : {self.MN["IP"] : "fe80::4950:b4e7:5b57:e2a8"},
#            self.DP2 : {self.MN["IP"] : "fe80::4950:b4e7:5b57:e2a7"},
            self.DP3 : {self.CN["IP"] : "fe80::3dcc:b07c:8605:f1b1"},
        }
        self.dms = {
            (self.MN["MAC"], self.MN["IP"]) : (self.DP1, self.LI_POOL[self.DP1][self.MN["IP"]]),
            (self.CN["MAC"], self.CN["IP"]) : (self.DP3, self.LI_POOL[self.DP3][self.CN["IP"]]),
        }
        self.OUTPORT = {
            (self.DP1, self.DP2) : 2,
            (self.DP1, self.DP3) : 2,
            (self.DP2, self.DP1) : 2,
            (self.DP2, self.DP3) : 2,
            (self.DP3, self.DP1) : 2,
            (self.DP3, self.DP2) : 3,
            (self.DP1, self.MN["IP"]) : (1, self.LI_POOL[self.DP1][self.MN["IP"]]),
            (self.DP2, self.MN["IP"]) : (1, self.LI_POOL[self.DP2][self.MN["IP"]]),
            (self.DP3, self.CN["IP"]) : (1, self.LI_POOL[self.DP3][self.CN["IP"]]),
        }
        self.dpid_to_datapath = {}
        print u"ip address pool初始化完毕!"
        print u"dms初始化完毕!"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = dpid_lib.dpid_to_str(datapath.id)
        self.dpid_to_datapath[dpid] = datapath
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        if dpid == self.DP1:
            # init mac_to_port
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][self.MN["MAC"]] = 1
            self.mac_to_port[dpid][self.CN["MAC"]] = 2
            # create flow for MN --> CN on DP1
            out_port = self.OUTPORT[(self.DP1, self.DP3)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.dms.get((self.CN["MAC"], self.CN["IP"]))[-1]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.MN["MAC"],
                                    eth_dst=self.CN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.MN["IP"],
                                    ipv6_dst=self.CN["IP"],
            )
            self.add_flow(datapath, 99, match, actions)

            # create flow for CN --> MN on DP1
            out_port = self.OUTPORT[(self.DP1, self.MN["IP"])][0]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.MN["IP"]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.LI_POOL[self.DP1][self.MN["IP"]],
            )
            self.add_flow(datapath, 99, match, actions)


        elif dpid == self.DP2:
            # init mac_to_port
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][self.MN["MAC"]] = 1
            self.mac_to_port[dpid][self.CN["MAC"]] = 2
            # create flow for MN --> CN on DP2
            out_port = self.OUTPORT[(self.DP2, self.DP3)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.dms.get((self.CN["MAC"], self.CN["IP"]))[-1]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.MN["MAC"],
                                    eth_dst=self.CN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.MN["IP"],
                                    ipv6_dst=self.CN["IP"],
            )
            self.add_flow(datapath, 99, match, actions)

            # create flow for CN --> MN on DP2
            out_port = self.OUTPORT[(self.DP2, self.MN["IP"])][0]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.MN["IP"]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.LI_POOL[self.DP2][self.MN["IP"]],
            )
            self.add_flow(datapath, 99, match, actions)

        elif dpid == self.DP3:
            # init mac_to_port
            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][self.MN["MAC"]] = 2
            self.mac_to_port[dpid][self.CN["MAC"]] = 1
            # create flow for CN --> MN on DP3
            out_port = self.OUTPORT[(self.DP3, self.DP1)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.dms.get((self.MN["MAC"], self.MN["IP"]))[-1]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.MN["IP"],
            )
            self.add_flow(datapath, 99, match, actions)

            # create flow for MN --> CN on DP3
            out_port = self.OUTPORT[(self.DP3, self.CN["IP"])][0]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.CN["IP"]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.MN["MAC"],
                                    eth_dst=self.CN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.MN["IP"],
                                    ipv6_dst=self.LI_POOL[self.DP3][self.CN["IP"]],
            )
            self.add_flow(datapath, 99, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)

    def update_flow(self, datapath, priority, match, actions, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(command=ofproto.OFPFC_MODIFY,
                                hard_timeout=timeout,
                                datapath=datapath,
                                priority=priority,
                                match=match,
                                instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        dpid = dpid_lib.dpid_to_str(datapath.id)
        self.mac_to_port.setdefault(dpid, {})

	if pkt.get_protocol(icmpv6.icmpv6):
	    print u" icmpv6 "
	    icmpv6_pkt = pkt.get_protocol(icmpv6.icmpv6)
	    print icmpv6_pkt.type_ , icmpv6_pkt.code

        pkt_ipv6 = None
        dst_ip = None
        src_ip = None
        if not pkt.get_protocol(ipv6.ipv6):
            pass
        else:
            pkt_ipv6 = pkt.get_protocol(ipv6.ipv6)
            dst_ip = pkt_ipv6.dst
            src_ip = pkt_ipv6.src
	    print src_ip , dst_ip

#        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        if src_ip and src == self.MN["MAC"] and self.OUTPORT.get((dpid, src_ip)) and (
                self.OUTPORT[(dpid, src_ip)][0] == in_port and self.dms.get((src, src_ip))[0] != dpid):
            print u"感知切换! 现在接入的AP是 %s" % dpid
            timestamp_start = datetime.now()
            """detect handoff,
            should add new flow for this dpid,
            and update flow for the other two dpid, note that (dpid, LI) will change.  
            """
            # create flow for MN --> CN on dpid
            out_port = self.OUTPORT[(dpid, self.DP3)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.dms.get((self.CN["MAC"], self.CN["IP"]))[-1]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.MN["MAC"],
                                    eth_dst=self.CN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.MN["IP"],
                                    ipv6_dst=self.CN["IP"],
            )
            self.add_flow(datapath, 99, match, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                out = parser.OFPPacketOut(datapath=datapath,
                                          buffer_id=msg.buffer_id,
                                          in_port=in_port,
                                          actions=actions,
                                          data=data)
                datapath.send_msg(out)

            # then redirect old dpid flow to new dpid
            old_dpid = self.dms.get((self.MN["MAC"], self.MN["IP"]))[0]
            out_port = self.OUTPORT[(old_dpid, dpid)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.LI_POOL[dpid][src_ip]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.dms.get((self.MN["MAC"], self.MN["IP"]))[-1],
            )
            self.update_flow(self.dpid_to_datapath[old_dpid], 99, match, actions)
            print u"旧AP的映射表重定向完毕!导向缓存数据包到新AP"
            
            # now should update dms
            self.dms[(self.MN["MAC"], self.MN["IP"])] = (dpid, self.LI_POOL[dpid][src_ip])
            print u"dms信息更新完毕!"

            # update flow for CN --> MN on DP3
            out_port = self.OUTPORT[(self.DP3, dpid)]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.dms.get((self.MN["MAC"], self.MN["IP"]))[-1]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.MN["IP"],
            )
            self.update_flow(self.dpid_to_datapath[self.DP3], 99, match, actions)
            print u"CN接入的AP映射表更新完毕!"

            # create flow for CN --> MN on dpid
            out_port = self.OUTPORT[(dpid, self.MN["IP"])][0]
            actions = [
                parser.OFPActionSetField(ipv6_dst=self.MN["IP"]),
                parser.OFPActionOutput(out_port),
            ]
            match = parser.OFPMatch(eth_src=self.CN["MAC"],
                                    eth_dst=self.MN["MAC"],
                                    eth_type=0x86dd,
                                    ipv6_src=self.CN["IP"],
                                    ipv6_dst=self.dms.get((self.MN["MAC"], self.MN["IP"]))[-1],
            )
            self.add_flow(datapath, 99, match, actions)
            print u"新AP适配映射表下发完毕!"
            timestamp_end = datetime.now()
            res_time = float((timestamp_end - timestamp_start).microseconds) / 1000
            print u"所耗时间: %.2f 毫秒" % res_time
            print u"~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
