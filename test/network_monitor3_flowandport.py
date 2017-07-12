from operator import attrgetter
from ryu.ofproto import ofproto_v1_3
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import setting

class MyMonitor13(simple_switch_13.SimpleSwitch13):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MyMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.port_stats = {}
        self.flow_stats = {}
	    self.stats = {}

        # 保存当前流量带宽
        self.current_bandwidth = {}

        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER,DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug("Register datapath: %16x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug("Unregister datapath: %16x", datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
	self.stats['flow'] = {}
        self.stats['port'] = {}
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            # 调用 network_resource_allocation
            # 
            # 分配完资源后，下发流表
            # add_flow()

    def _request_stats(self, datapath):
        # send reqeust to datapath.
        self.logger.debug("send stats request: %16x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # handle port statistics. 
        # 
        # 即 network_slice_monitor
        # 
        # 
        body = ev.msg.body
	    dpid = ev.msg.datapath.id
	
        self.logger.info('datapath         port    '
                         'rx-pkts   rx-bytes  rx-error '
                         'tx-pkts   tx-bytes  tx-error    speed' )
        self.logger.info('-----------------  --------'
                         '--------  --------  -------- '
                         '--------  --------  --------  --------')
        for stat in sorted(body, key=attrgetter('port_no')):

            port_no = stat.port_no
            speed = 0
            if port_no != ofproto_v1_3.OFPP_LOCAL:
                key = (dpid, port_no)
                value = (stat.tx_bytes, stat.rx_bytes, stat.rx_errors,
                         stat.duration_sec, stat.duration_nsec)

                self._save_stats(self.port_stats, key, value, 5)

                # Get port speed.
                pre = 0
                period = setting.MONITOR_PERIOD
                tmp = self.port_stats[key]
                if len(tmp) > 1:
                    pre = tmp[-2][0] + tmp[-2][1]
                    period = self._get_period(tmp[-1][3], tmp[-1][4],
                                              tmp[-2][3], tmp[-2][4])

                speed = self._get_speed(
                    self.port_stats[key][-1][0] + self.port_stats[key][-1][1],
                    pre, period)

                self.logger.info('%16x %8x %8d %8d %8d %8d %8d %8d  %8d',
                            ev.msg.datapath.id, stat.port_no,
                            stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                            stat.tx_packets, stat.tx_bytes, stat.tx_errors,speed)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        # handle flow entry statistics.
        # 
        # 即 network_slice_monitor
        # 
        # 
        body = ev.msg.body
	    dpid = ev.msg.datapath.id

        pkt = packet.Packet(ev.msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        src = eth.src
        dst = eth.dst

	    self.stats['flow'][dpid] = body
        self.flow_stats.setdefault(dpid, {})

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes  speed')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------  -------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

	        key = (stat.match['in_port'],  stat.match.get('ipv4_dst'),
                   stat.instructions[0].actions[0].port)
            value = (stat.packet_count, stat.byte_count,
                     stat.duration_sec, stat.duration_nsec)
            self._save_stats(self.flow_stats[dpid], key, value, 5)

	        # Get flow's speed.
            pre = 0
            period = setting.MONITOR_PERIOD
            tmp = self.flow_stats[dpid][key]
            if len(tmp) > 1:
                pre = tmp[-2][1]
                period = self._get_period(tmp[-1][2], tmp[-1][3],
                                          tmp[-2][2], tmp[-2][3])
            
            speed = self._get_speed(self.flow_stats[dpid][key][-1][1],
                                    pre, period)
            
            # 保存分片的带宽
            if src == 10.0.0.1 or src == 10.0.0.2 or src ==10.0.0.3:
                self.current_bandwidth[src] = speed 

            self.logger.info('%016x %8x %17s %8x %8d %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count,speed)

    def _save_stats(self, _dict, key, value, length):
        if key not in _dict:
            _dict[key] = []
        _dict[key].append(value)

        if len(_dict[key]) > length:
            _dict[key].pop(0)
            
    def _get_speed(self, now, pre, period):
        if period:
            return (now - pre) / (period)
        else:
            return 0
    def _get_period(self, n_sec, n_nsec, p_sec, p_nsec):
        return self._get_time(n_sec, n_nsec) - self._get_time(p_sec, p_nsec)
    def _get_time(self, sec, nsec):
        return sec + nsec / (10 ** 9)
