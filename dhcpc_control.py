# -*- coding:utf-8 -*-
from dhcp_client_fsm import *
from dhcp_sup import PseudoThread
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import *
from scapy.config import conf

import logging, threading

logger = logging.getLogger('dhcp_client')
logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s', level = logging.WARNING)

def dhcp_sniff_pkt_cb(packet):
    if (packet[BOOTP].op == 2):
        for client in DhcpcControlCenter.get_dhcpc_list():
            entry = client.entry
            if (client.get_dhcpc_state() == DHCPS_BIND):
                continue
            if (entry.req_attr['xid'] == packet[BOOTP].xid and entry.req_attr['chaddr'] == packet[BOOTP].chaddr[:len(entry.req_attr['chaddr'])]):
                # logger.debug('SRC[%s] DST[%s] [%s]' % (packet[IP].src, packet[IP].dst, packet[BOOTP].yiaddr))
                for mess in packet["DHCP options"].options:
                    if (len(mess) == 2 and mess[0] == 'message-type'):
                        client.rc_pkt = packet
                        if (mess[1] == 2): #offer
                            DHCPC_ENTRY.create_fsm_event(client, DH_Recv_Offer)
                            break
                        elif (mess[1] == 5): #ack
                            DHCPC_ENTRY.create_fsm_event(client, DH_Recv_Ack)
                            break
                        else:
                            logger.debug("curr state(%d) recv(%d)pkt" %(client.get_dhcpc_state(), mess[1])) # 可能是NAK
            else:
                #logger.debug("not except packet, ignore")
                pass

def show_state():
    logger.debug("all client count:%d bound count:%d , ..." % (DhcpcControlCenter.get_dhcpc_cnt(), DhcpcControlCenter.get_dhcpc_bind_cnt()))
    if (DhcpcControlCenter.get_dhcpc_cnt() == DhcpcControlCenter.get_dhcpc_bind_cnt()):
        for client in DhcpcControlCenter.get_dhcpc_list():
            client.bound_show()
        return
    PseudoThread.async_run_later_event(show_state, DHCPC_SHOW_BIND_TIME)

#这个应该是单实例
class DhcpcControlCenter():
    # 从dhcp server获取地址后，可以对ping请求报文进行回应
    sup = sup_manage()
    sup.start()
    # scapy配置
    conf.sniff_promisc = conf.promisc = 0
    #conf.checkIPaddr = 1
    conf.use_pcap = True
    conf.logLevel = logging.ERROR

    # ctrl_center配置
    __client_list = []
    __dhcpc_bound_nums = 0
    __clients_re_trans_list = []

    # nty bind 回调设置
    nty_userbind_gen_cb = None
    set_dhcpc_retrans_check = None

    def set_nty_userbind_gen_cb(cb):
        DhcpcControlCenter.nty_userbind_gen_cb = cb

    def create_new_detail_client(self, pkt_cfg):
        DhcpcControlCenter.__client_list.append(DHCPC_ENTRY(1, pkt_cfg))
    def create_new_client(self, mode, pkt_cfg):
        if (mode == 1):
            self.create_new_detail_client(pkt_cfg)
        else:
            DhcpcControlCenter.__client_list.append(DHCPC_ENTRY(0, None))

    def userbind_entryinfo_gen_cb(self, entry):
        DhcpcControlCenter.__dhcpc_bound_nums += 1
        DhcpcControlCenter.sup.add_dhcp_bind(entry.get_attr['get_ip'], entry.req_attr['mac'])
        DhcpcControlCenter.sup.set_gateway_by_dhcp(entry.get_attr['server_id'])
        DhcpcControlCenter.nty_userbind_gen_cb(DhcpcBindsEntryInfo(entry.get_attr['get_ip'], entry.req_attr['mac']))

    def dhcpc_retrans_check(client):
        if (client.get_dhcpc_state() == DHCPS_BIND):
            if client in DhcpcControlCenter.__clients_re_trans_list:
                DhcpcControlCenter.__clients_re_trans_list.remove(client)
        else:
            if client not in DhcpcControlCenter.__clients_re_trans_list:
                DhcpcControlCenter.__clients_re_trans_list.append(client)

    def get_dhcpc_cnt():
        return len(DhcpcControlCenter.__client_list)

    def get_dhcpc_bind_cnt():
        return DhcpcControlCenter.__dhcpc_bound_nums

    def get_dhcpc_list():
        return DhcpcControlCenter.__client_list

    def clearALL(self):
        DhcpcControlCenter.__client_list = []
        DhcpcControlCenter.__dhcpc_bound_nums = 0

    def start(self):
        for client in DhcpcControlCenter.get_dhcpc_list():
            client.start()
    def __init__(self):
        # 注册通知函数
        DHCPC_ENTRY.set_nty_userbind_gen_cb(self.userbind_entryinfo_gen_cb)
        DHCPC_ENTRY.set_dhcpc_retrans_check(DhcpcControlCenter.dhcpc_retrans_check)

        # dhcpc_main配置
        self.async_sniff_replypkt_thread = None
        self.dhcpc_main_thread = None
        self.nums = 0
        
        # 开启debug
        # self.set_dhcpc_log_level(logging.DEBUG)

    def set_dhcpc_log_level(self, level):
        logger.setLevel(level)

    def cfg_init(self, iface, nums, mode, pkt_cfg):
        self.mode = mode
        self.pkt_cfg = pkt_cfg
        conf.iface = iface
        self.nums = nums
        logger.debug("<IN cfg_init> iface(%s), nums(%d)" % (conf.iface, self.nums))

    def async_dhcpc_start(self):
        if (self.async_sniff_replypkt_thread is None):
            self.async_sniff_replypkt_thread = AsyncSniffer(lfilter=lambda pkt : DHCP in pkt, iface = conf.iface, prn = dhcp_sniff_pkt_cb)
            self.async_sniff_replypkt_thread.start()
        if (self.dhcpc_main_thread is None):
            self.dhcpc_main_thread = threading.Thread(target=self.dhcpc_main_thread_func)
            self.dhcpc_main_thread.setDaemon(True)
            self.dhcpc_main_thread.start()
        else:
            for _ in range(self.nums):
                self.create_new_client(self.mode, self.pkt_cfg)
            self.start()
            PseudoThread.async_run_later_event(show_state, DHCPC_SHOW_BIND_TIME)

    def dhcpc_main_thread_func(self):
        for i in range(self.nums):
            self.create_new_client(self.mode, self.pkt_cfg)
        self.start()
        PseudoThread.async_run_later_event(DHCPC_ENTRY.deal_fsm_event, 0.1)
        PseudoThread.async_run_now(show_state)
        PseudoThread.async_run_later_event(DhcpcControlCenter.dhcp_re_trans, DHCPC_PKT_RETRANS_TIME)
        #主线程不退出
        PseudoThread.run_forever()

    def dhcp_re_trans():
        for client in DhcpcControlCenter.__clients_re_trans_list:
            DHCPC_ENTRY.create_fsm_event(client, DH_ReSend_Packet)
        PseudoThread.async_run_later_event(DhcpcControlCenter.dhcp_re_trans, DHCPC_PKT_RETRANS_TIME)