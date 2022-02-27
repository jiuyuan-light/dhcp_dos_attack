# -*- coding:utf-8 -*-
from random import randint
from tkinter.messagebox import NO
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import *
from scapy.utils import mac2str, hex_bytes
from socket import *
from multiprocessing import shared_memory
from dhcp_sup import *
import json

logger = logging.getLogger('dhcp_client')

SRC_PORT = 68
DST_PORT = 67
DHCPC_PKT_RETRANS_TIME = 10
DHCPC_SHM_WITH_HANDLE_NAME = "dhcpc_shm_with_keyname"

class m_shm():
    def __init__(self, name) -> None:
        self.shm = shared_memory.SharedMemory(name=name, create=False)
        self.buf = self.shm.buf
        self.start = 0
        self.write_curr = 0
        self.read_curr = 0
        self.end = self.shm.size - 1 # [0, self.shm.size)
        self.spilter = '\n'
        self.read_fix = 256
        self.eof = '\0'

        # self.shm.close() # 关闭共享内存
        # self.shm.unlink() # 释放共享内存，也可以由B进程释放
    def write_one_msg(self, cstr):
        self.write(cstr + self.spilter)

    def write(self, cstr):
        bytes = cstr.encode('utf-8')
        length = len(bytes)

        if (self.write_curr + length > self.end): #共享内存不足
            return -1
        self.write_with_bytes(bytes, length)

    def write_with_bytes(self, bytes, bytes_len):
        self.buf[self.write_curr:self.write_curr + bytes_len] = bytes
        self.write_curr += bytes_len

        self.buf[self.write_curr:self.write_curr + len(self.eof.encode('utf-8'))]  = self.eof.encode('utf-8')

    def read_one_msg(self):
        s = b''
        while (True):
            s += self.read_with_bytes(self.read_fix)
            index = s.decode().find(self.spilter)
            if (index != -1):
                s = s[:index]
                self.read_curr = len(self.spilter.encode('utf-8')) + self.read_curr - (self.read_fix - index % self.read_fix) #skip \n
                return s.decode()
            if (s.decode().find(self.eof) != -1 or self.read_curr == self.end):
                return None
    #Works only on read descriptors
    def lseek(self, offset=0):
        self.read_curr = self.start

    def read_with_bytes(self, bytes_len):
        if (self.read_curr + bytes_len > self.end):
            bytes_len = self.end - self.read_curr
        s = self.buf[self.read_curr : self.read_curr + bytes_len].tobytes()
        self.read_curr += bytes_len
        return s

    def read_all(self):
        if (self.write_curr == self.start):
            return None
        bytes = self.buf[:self.write_curr - len(self.eof.encode('utf-8'))].tobytes()
        self.read_curr = self.write_curr
        return bytes.decode().split(self.spilter)

    def close(self):
        self.shm.close()
    def unlink(self):
        self.shm.unlink()

# fix part + [0 - 65535]
def randomMAC(serial=False):
    if (not hasattr(randomMAC, 'rand')): #hasattr函数的第一个变量为当前函数名，第二个为变量名，加单引号
        randomMAC.rand = 0 
    randomMAC.rand += 1
    if (serial):
        mac = [ 0x08, 0x00, 0x27, 
                0x00, 
                randomMAC.rand >> 8 & 0xff, 
                randomMAC.rand & 0xff
            ]
    else:
        mac = [ 
            0x08, 0x00, 0x27,
            random.randint(0x00, 0xff), 
            random.randint(0x00, 0xff), 
            random.randint(0x00, 0xff)
        ]
    return ':'.join(map(lambda x: "%02x" % x, mac))

class M_DHCP_CLIENT_ENTRY():
    _giaddr_map = {}
    def __init__(self, mac = None, xid = None, giaddr = None):
        if xid is None:
            self.fixxid = False
        else:
            self.fixxid = True
        
        self.req_attr = {
                            'giaddr' : giaddr,
                            'xid' : xid,
                            'mac' : mac,
                            'chaddr' : None,
                            'hostname' : 'nbk',
                            'interval' : 10, # 重传时间，暂时没用到，目前统一重传
                            'req_list' : [1, 2, 3, 6, 12, 15, 17, 26, 28, 33, 40 , 41, 42, 121, 119, 249, 252],
                                }
        self.get_attr = {   'server_id' : None,
                            'get_ip' : None,
                                }
    @property
    def giaddr_mac(self):
        if self.req_attr['giaddr'] is None:
            return None
        if self.req_attr['giaddr'] in M_DHCP_CLIENT_ENTRY._giaddr_map:
           return M_DHCP_CLIENT_ENTRY._giaddr_map[self.req_attr['giaddr']]
        else:
            M_DHCP_CLIENT_ENTRY._giaddr_map[self.req_attr['giaddr']] = randomMAC()
            return M_DHCP_CLIENT_ENTRY._giaddr_map[self.req_attr['giaddr']]
    def add_giaddr2sup_manage(self):
        M_DHCP_CLIENT_CENTER.sup.add_dhcp_bind(self.req_attr['giaddr'], self.giaddr_mac)

    def get_attr_by_dhcp(self, pkt):
        for mess in pkt['DHCP options'].options:
            if (len(mess) == 2 and mess[0] == "server_id"):
                self.get_attr['server_id'] = mess[1]
        self.get_attr['get_ip'] = pkt[BOOTP].yiaddr

    def gen_request(self):
        dhcp_pkt = DHCP(options=[("message-type", "request"), 
        ("client_id", hex_bytes('01')+self.req_attr['chaddr']), 
        ("param_req_list", self.req_attr['req_list']),
        ("max_dhcp_size", 576),
        ("hostname", self.req_attr['hostname']),
        ("requested_addr", self.get_attr['get_ip']), 
        ("server_id", self.get_attr['server_id']), 
        "end"])
        bootp_pkt = BOOTP(chaddr = self.req_attr['chaddr'], xid = self.req_attr['xid'], yiaddr = self.get_attr['get_ip'], flags=0x8000)
        udp_header = UDP(sport=SRC_PORT, dport=DST_PORT)
        ip_header = IP(src = ZERO_IP, dst = BROADSTCAST_IP)
        eth_header = Ether(src = self.req_attr['mac'], dst=BROADSTCAST_MAC)

        if self.req_attr['giaddr'] != None:
            return Ether(src = self.giaddr_mac, dst=BROADSTCAST_MAC) / IP(src = self.req_attr['giaddr'], dst = BROADSTCAST_IP) / udp_header / \
            BOOTP(chaddr = self.req_attr['chaddr'], xid = self.req_attr['xid'], yiaddr = self.get_attr['get_ip'], giaddr = self.req_attr['giaddr'], flags=0x8000) \
            / dhcp_pkt

        return eth_header / ip_header / udp_header / bootp_pkt / dhcp_pkt
    def gen_discover(self):
        if self.req_attr['mac'] is None:
            self.req_attr['mac'] = randomMAC()
        if self.fixxid is not True:
            self.req_attr['xid'] = randint(0, 0xffffffff)
        self.req_attr['chaddr'] = mac2str(self.req_attr['mac'])

        dhcp_pkt = DHCP(options=[("message-type", "discover"),
                        ("client_id", hex_bytes('01')+self.req_attr['chaddr']), 
                        ("param_req_list", self.req_attr['req_list']),
                        ("max_dhcp_size", 576),
                        ("hostname", self.req_attr['hostname']),
                        "end"])

        bootp_pkt = BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], flags=0x8000)
        udp_header = UDP(sport=SRC_PORT, dport=DST_PORT)
        ip_header = IP(src = ZERO_IP, dst = BROADSTCAST_IP)
        eth_header = Ether(src = self.req_attr['mac'], dst=BROADSTCAST_MAC)

        if self.req_attr['giaddr'] != None:
            self.add_giaddr2sup_manage()
            return Ether(src = self.giaddr_mac, dst=BROADSTCAST_MAC) / IP(src = self.req_attr['giaddr'], dst = BROADSTCAST_IP) / udp_header / \
            BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], giaddr = self.req_attr['giaddr'], flags=0x8000) \
            / dhcp_pkt

        return  eth_header / ip_header / udp_header / bootp_pkt / dhcp_pkt

#event
DH_Send_Discover    = 0
DH_ReSend_Packet    = 1
DH_Recv_Offer       = 2
DH_Select_Done      = 3
DH_Recv_Ack         = 4
DH_Admin_stop       = 5
DH_NO_RECV_REPLY   = 6
#fsm status
DHCPS_INIT          = 0
DHCPS_INIT_PROC     = 1
DHCPS_SELECT        = 2
DHCPS_REQUEST_PROC  = 3
DHCPS_BIND          = 4
DHCPS_STOP          = 5

class M_DHCP_CLIENT_FSM():
    def __init__(self, id = 0, mac = None, xid = None, giaddr = None) -> None:
        self.id = id
        self.entry = M_DHCP_CLIENT_ENTRY(mac, xid, giaddr)
        self.rc_pkt = None
        self.gen_pkt = None
        self.retrans_times = 0

        self.lock = threading.RLock()
        self.current_state = DHCPS_STOP

    def start(self):
        self.current_state = DHCPS_INIT
        self.init(None)

    def get_fsm_fun(self):
        func = self.stop
        if (self.current_state == DHCPS_INIT):
            func = self.init
        elif (self.current_state == DHCPS_INIT_PROC):
            func = self.init_proc
        elif (self.current_state == DHCPS_SELECT):
            func = self.select
        elif (self.current_state == DHCPS_REQUEST_PROC):
            func = self.request_proc
        elif (self.current_state == DHCPS_BIND):
            func = self.bind
        elif (self.current_state == DHCPS_STOP):
            func = self.stop
        return func

    def process_event(self, event):
        if (self.current_state == DHCPS_INIT and event == DH_Send_Discover):
            self.current_state = DHCPS_INIT_PROC
        elif (self.current_state == DHCPS_INIT_PROC and event == DH_Recv_Offer):
            self.current_state = DHCPS_SELECT
        elif (self.current_state == DHCPS_INIT_PROC and event == DH_ReSend_Packet):
            self.current_state = DHCPS_INIT_PROC
        elif (self.current_state == DHCPS_SELECT and event == DH_Select_Done):
            self.current_state = DHCPS_REQUEST_PROC
        elif (self.current_state == DHCPS_REQUEST_PROC and event == DH_Recv_Ack):
            self.current_state = DHCPS_BIND
        elif (self.current_state == DHCPS_REQUEST_PROC and event == DH_ReSend_Packet):
            self.current_state = DHCPS_REQUEST_PROC
        elif (self.current_state == DHCPS_REQUEST_PROC and event == DH_NO_RECV_REPLY):
            self.current_state = DHCPS_INIT
        else: # 有一些可以忽略的异常情况，比如request_porc状态收到offer这是有可能的
            return
        self.get_fsm_fun()(event)
        

    def bound_show(self):
        if (self.get_dhcpc_state() == DHCPS_BIND):
            logger.debug("local bound, id:%d :ip(%s), mac(%s), server(%s)\n" % (self.id, self.entry.get_attr['get_ip'], self.entry.req_attr['mac'], self.entry.get_attr['server_id']))

    def write(self):
        M_DHCP_CLIENT_CENTER.sup.add_dhcp_bind(self.entry.get_attr['get_ip'], self.entry.req_attr['mac'])
        M_DHCP_CLIENT_CENTER.sup.set_gateway_by_dhcp(self.entry.get_attr['server_id'])
        if (M_DHCP_CLIENT_CENTER.shm is None):
            return
        msg = self.entry.get_attr['get_ip'] +',' + self.entry.req_attr['mac'] +',' + self.entry.get_attr['server_id']
        logger.debug("add to gui, id:%d msg(%s)" % (self.id, msg))
        M_DHCP_CLIENT_CENTER.shm.write_one_msg(msg)
    def sync_fsm_event(self, event):
        self.lock.acquire()
        state = self.get_dhcpc_state()
        if (event == DH_ReSend_Packet and (state == DHCPS_INIT_PROC or state == DHCPS_REQUEST_PROC)
        or (event == DH_Recv_Offer and state == DHCPS_INIT_PROC)
        or (event == DH_Recv_Ack and state == DHCPS_REQUEST_PROC)
        ):
            self.process_event(event)
        self.lock.release()

    def get_dhcpc_state(self):
        return self.current_state

    def init(self, event):
        # logger.debug("inci DHCPS_INIT")
        self.process_event(DH_Send_Discover)

    def init_proc(self, event):
        # logger.debug("inci DHCPS_INIT_PROC")

        if (event == DH_Send_Discover):
            self.gen_pkt = self.entry.gen_discover()

            if self not in M_DHCP_CLIENT_CENTER.clients_re_trans_list:
                M_DHCP_CLIENT_CENTER.clients_re_trans_list.append(self)
            sendp(self.gen_pkt, iface = conf.iface, verbose = False)
            # sendp(Discover, iface = conf.iface)
            #等待offer中
        elif (event == DH_ReSend_Packet):
            sendp(self.gen_pkt, iface = conf.iface, verbose = False)
        else:
            logger.debug("DHCPS_INIT_PROC", event)
            #client.fsm.process_event(DH_Admin_stop)
        logger.debug("send a discover")
    def select(self, event):
        #logger.debug("inci DHCPS_INIT_SELECT")
        if (event == DH_Recv_Offer):
            #目前收到一个offer立即去发送request，不选择offer
            self.process_event(DH_Select_Done)
        else:
            logger.debug("DHCPS_SELECT", event)
            #client.fsm.process_event(DH_Admin_stop)

    def request_proc(self, event):
        #logger.debug("inci DHCPS_REQUEST_PROC")
        if (event == DH_Select_Done or event == DH_ReSend_Packet):
            if (event != DH_ReSend_Packet):
                self.retrans_times = 0
            else:
                self.retrans_times += 1

            if (self.retrans_times > M_DHCP_CLIENT_CENTER.max_retrans_times):
                self.process_event(DH_NO_RECV_REPLY)
                return

            self.entry.get_attr_by_dhcp(self.rc_pkt)
            pkt = self.entry.gen_request()

            if self not in M_DHCP_CLIENT_CENTER.clients_re_trans_list:
                M_DHCP_CLIENT_CENTER.clients_re_trans_list.append(self)

            sendp(pkt, iface = conf.iface)
            #等待ack
        else:
            logger.debug("DHCPS_REQUEST_PROC", event)
            #client.fsm.process_event(DH_Admin_stop)

    def bind(self, event):
        #logger.debug("inci DHCPS_BIND")
        if (event == DH_Recv_Ack):
            #进入bind状态
            self.entry.get_attr_by_dhcp(self.rc_pkt)

            if self in M_DHCP_CLIENT_CENTER.clients_re_trans_list:
                M_DHCP_CLIENT_CENTER.clients_re_trans_list.remove(self)
            M_DHCP_CLIENT_CENTER.dhcpc_bound_count_inc()
            
            self.entry.req_attr['xid'] = 0x0
            self.write()
        else:
            pass
            #client.fsm.process_event(DH_Admin_stop)

    def stop(self, event):
        #logger.debug("inci DHCPS_STOP")
        pass

class M_DHCP_CLIENT_CENTER():
    __client_list = []
    __dhcpc_nums = 0
    max_retrans_times = 3
    __dhcpc_bound_nums = 0
    clients_re_trans_list = []

    try:
        shm = m_shm(DHCPC_SHM_WITH_HANDLE_NAME)
    except FileNotFoundError:
        logger.error("open shm file fail, maybe can ignore")
        shm = None
    
    # 从dhcp server获取地址后，可以对ping请求报文进行回应
    sup = sup_manage()
    sup.start()
    def __init__(self, nums = 1, need_cfg = False) -> None:
        M_DHCP_CLIENT_CENTER.__dhcpc_nums = nums

        if need_cfg:
            logger.debug("load cfgfile:" + need_cfg)
            with open(need_cfg) as f:
                cfgs = json.load(f)

        for i in range(nums):
            mac = None
            xid = None
            giaddr = None
            if need_cfg:
                if str(i) in cfgs:
                    cfg = cfgs[str(i)]
                    if len(cfg['mac']) != 0:
                        mac = cfg['mac']
                    if cfg['xid'] != 0:
                        xid = cfg['xid']
                    if len(cfg['giaddr']) != 0:
                        giaddr = cfg['giaddr']
            client = M_DHCP_CLIENT_FSM(i, mac, xid, giaddr)
            M_DHCP_CLIENT_CENTER.__client_list.append(client)

    def get_dhcpc_count():
        return M_DHCP_CLIENT_CENTER.__dhcpc_nums

    def get_dhcpc_bound_count():
        return M_DHCP_CLIENT_CENTER.__dhcpc_bound_nums

    def dhcpc_bound_count_inc():
        M_DHCP_CLIENT_CENTER.__dhcpc_bound_nums += 1

    def get_dhcpc_list():
        return M_DHCP_CLIENT_CENTER.__client_list

    def start(self):
        for client in M_DHCP_CLIENT_CENTER.get_dhcpc_list():
            client.start()