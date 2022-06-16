# -*- coding:utf-8 -*-
from scapy.layers.inet import *
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import sendp
from scapy.all import *
from collections import namedtuple
import copy
from dhcp_client_fsm import *
import gevent
from PyQt6.QtNetwork import QNetworkInterface

BROADSTCAST_MAC     = 'ff:ff:ff:ff:ff:ff'
BROADSTCAST_IP      = '255.255.255.255'
ZERO_IP             = '0.0.0.0'
ZERO_MAC = '00:00:00:00:00:00'

logger = logging.getLogger('dhcp_client')

class NetCardInfo(QNetworkInterface):
    def __init__(self):
        self.net_itfs = QNetworkInterface.allInterfaces()
    def NetCardNameList(self):
        card = list()
        for itf in self.net_itfs:
            if (itf.type() == QNetworkInterface.InterfaceType.Virtual
                or itf.flags() & QNetworkInterface.InterfaceFlag.IsLoopBack
                or not itf.flags() & QNetworkInterface.InterfaceFlag.IsUp):
                continue
            card.append(itf.humanReadableName())
        return card

class PseudoThread():
    @staticmethod
    def async_run_later_event(func, seconds, *args, **kwargs):
        gevent.spawn_later(seconds, func, *args, **kwargs)
    @staticmethod
    def async_run_now(func, *args, **kwargs):
        gevent.spawn(func, *args, **kwargs)
    
    @staticmethod
    def run_forever():
        gevent.wait()

# 维护一张arp表用以响应网关. mac是伪造的，ip是从dhcp获取的，当网关发起arp-request时，对其进行回应。
class ARP_TABLE():
    __user_list = list()
    __gateway_list = list()
        # 创建具名元组构造器，具名元组名称是__entry，字段名是ip和mac
    __entry = namedtuple('mac_ip_entry', ('ip_address', 'mac_address'))

    # 不能添加重复的ip
    def update_user(self, ip, mac):
        for user in ARP_TABLE.__user_list:
            if user[0] == ip.strip() and user[1] == mac.strip():
                return
            elif (user[0] == ip.strip()):
                ARP_TABLE.__user_list.remove(user)
        ARP_TABLE.__user_list.append(ARP_TABLE.__entry(ip, mac))
        logger.debug("add a user:ip(%s), mac(%s)" % (ip, mac))
    def update_gateway(self, ip, mac):
        for gateway in ARP_TABLE.__gateway_list:
            if gateway[0] == ip.strip() and gateway[1] == mac.strip():
                return
            elif (gateway[0] == ip.strip()):
                ARP_TABLE.__gateway_list.remove(gateway)
        ARP_TABLE.__gateway_list.append(ARP_TABLE.__entry(ip, mac))

    def get_user_mac(self, ip):
        for user_ip, user_mac in ARP_TABLE.__user_list:
            if user_ip == ip:
                return user_mac
        return None
    def get_one_user(self):
        for user_ip, user_mac in ARP_TABLE.__user_list:
            return (user_ip, user_mac)
        return None
    def get_gateway_mac(self, ip):
        for gateway_ip, gateway_mac in ARP_TABLE.__gateway_list:
            if gateway_ip == ip:
                return gateway_mac
        return None
    # @property 暂时不需要
    def get_user_table(self):
        return list(ARP_TABLE.__user_list)
    # for test
    def get_gateway_table(self):
        return list(ARP_TABLE.__gateway_list)
    def is_in(self, ip):
        for user in ARP_TABLE.__user_list:
            if ip in user:
                return True
        return False

class sup_manage(object):
    _instance_lock = threading.Lock()
    def __init__(self) -> None:
        self.arp_table = ARP_TABLE()
        # self.arp_table.update_user('192.168.56.101', '52:54:00:00:00:01')
        self._arpt = AsyncSniffer(lfilter=lambda pkt: (ARP in pkt and pkt[ARP].op == 1) or (ICMP in pkt and pkt[ICMP].type == 8), 
                iface = conf.iface, prn = self.sniff_req_pkt_deal)
        self._server_id = None
    def add_dhcp_bind(self, ip, mac):
        self.arp_table.update_user(ip, mac)
        self.send_free_arp(ip, mac)
    def send_free_arp(self, ip, mac):
        arp = self.mk_arp_request(ip, ip, mac)

        sendp(arp, iface = conf.iface)
    def __new__(cls, *args, **kwargs):
        if not hasattr(sup_manage, "_instance"):
            with sup_manage._instance_lock:
                if not hasattr(sup_manage, "_instance"):
                    sup_manage._instance = object.__new__(cls)  
        return sup_manage._instance
    def start(self):
        self._arpt.start()
        PseudoThread.async_run_now(self.its_active)
    def join(self):
        self._arpt.join()
    def get_gateway_from_dhcp(self):
        return self._server_id
    def set_gateway_by_dhcp(self, ip):
        if (self._server_id == ip):
            return
        self._server_id = ip
    def get_oneuser_from_dhcp(self):
        return self.arp_table.get_one_user()
    def send_icmp_request_by_ipmac_table(self):
        for ip, mac in self.arp_table.get_user_table():
            dst_mac = self.get_mac_by_dstip(conf.iface, self.get_gateway_from_dhcp())
            if (dst_mac is None):
                continue
            icmp_req = self.mk_icmp_request(ip, self.get_gateway_from_dhcp(), mac, dst_mac=dst_mac)
            sendp(icmp_req, iface = conf.iface)
    def mk_arp_request(self, src_ip, dst_ip, src_mac):
        l2_header = Ether(src=src_mac, dst=BROADSTCAST_MAC)
        arp_data = ARP(hwtype = 0x1, ptype = 0x0800, hwlen = 6, plen = 4, \
        hwsrc = src_mac, \
        psrc = src_ip, \
        pdst = dst_ip, \
        hwdst = ZERO_MAC)
        return l2_header / arp_data

    def mk_arp_reply(self, src_ip, dst_ip, src_mac, dst_mac):
        l2_header = Ether(src=src_mac, dst=dst_mac)
        arp_data = ARP(hwtype = 0x1, ptype = 0x0800, hwlen = 6, plen = 4, op = 2,\
        hwsrc = src_mac, \
        psrc = src_ip, \
        pdst = dst_ip, \
        hwdst = dst_mac)
        return l2_header / arp_data

    def mk_icmp_request(self, src_ip, dst_ip, src_mac, dst_mac):
        l2_header = Ether(src=src_mac, dst=dst_mac)
        l3_header = IP(src=src_ip, dst=dst_ip)
        l3_icmp = ICMP(type = 8, id = random.randint(0, 0xffff), seq = random.randint(0, 0xffff))

        return ( l2_header / l3_header / l3_icmp )

    def get_mac_by_arp(self, iface, src_ip, dst_ip, src_mac):
        arp_req = self.mk_arp_request(src_ip, dst_ip, src_mac)
        responses, _ = srp(arp_req, timeout=1, iface = iface)
        for _, r in responses:
            self.arp_table.update_gateway(dst_ip, r[Ether].src)
            return r[Ether].src
        return None

    def get_mac_by_dstip(self, iface, dst_ip):
        # find in table
        mac = self.arp_table.get_gateway_mac(dst_ip)
        if (mac is None):
            user = self.get_oneuser_from_dhcp()
            return self.get_mac_by_arp(iface, user[0], dst_ip, user[1])
        return mac

    # 抓取arp/icmp请求，如果请求在arp表中，进行回应
    def sniff_req_pkt_deal(self, packet):
        if (packet[Ether].type == 0x0806 and packet[ARP].op == 1): # ARP REQUEST
            if (self.arp_table.is_in(packet[ARP].pdst)):
                if (packet[ARP].pdst == packet[ARP].psrc):
                    logger.debug("send a free-arp for " + packet[ARP].pdst)
                    return
                arp = self.mk_arp_reply(packet[ARP].pdst, packet[ARP].psrc, self.arp_table.get_user_mac(packet[ARP].pdst), packet[ARP].hwsrc)

                sendp(arp, iface = conf.iface)
        elif (ICMP in packet and packet[ICMP].type == 8): #ICMP REQUEST
            if (self.arp_table.is_in(packet[IP].dst)):
                icmp_reply = copy.deepcopy(packet)
                icmp_reply[Ether].src = packet[Ether].dst
                icmp_reply[Ether].dst = packet[Ether].src
                icmp_reply[IP].src = packet[IP].dst
                icmp_reply[IP].dst = packet[IP].src
                icmp_reply[ICMP].type = 0
                icmp_reply[ICMP].chksum = None
                # logger.debug("#1", arp_table.get_gateway_table())
                sendp(icmp_reply, iface = conf.iface)
    def its_active(self):
        self.send_icmp_request_by_ipmac_table()
        PseudoThread.async_run_later_event(self.its_active, 30)

if __name__ == '__main__':
    sup = sup_manage()

    sup.start()
    sup.join()