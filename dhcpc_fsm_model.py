from random import randint
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import *
from scapy.utils import mac2str, hex_bytes
from socket import *
from dhcp_sup import *
from dhcpc_utils import NonBlockingQueueSimpleFactory

from state_machine import State, Event, acts_as_state_machine, after, before, InvalidStateTransition

logger = logging.getLogger('dhcp_client')

SRC_PORT = 68
DST_PORT = 67
DHCPC_PKT_RETRANS_TIME  = 10
DHCPC_SHOW_BIND_TIME    = 3

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

class DHCPC_PKT_CFG():
    def __init__(self, pkt_cfg) -> None:
        self.pkt_cfg = pkt_cfg
    def get_op(self):
        return self.pkt_cfg.get_op()
    def get_htype(self):
        return self.pkt_cfg.get_htype()
    def get_hops(self):
        return self.pkt_cfg.get_hops()
    def get_xid(self):
        return self.pkt_cfg.get_xid()
    def get_secs(self):
        return self.pkt_cfg.get_secs()
    def get_flags(self)->str:
        return self.pkt_cfg.get_flags()
    def get_ciaddr(self)->str:
        return self.pkt_cfg.get_ciaddr()
    def get_yiaddr(self)->str:
        return self.pkt_cfg.get_yiaddr()
    def get_giaddr(self)->str:
        return self.pkt_cfg.get_giaddr()
    def get_chaddr(self)->str:
        return self.pkt_cfg.get_chaddr()
    def get_sname(self):
        return self.pkt_cfg.get_sname()
    def get_file(self):
        return self.pkt_cfg.get_file()
    def get_ops(self):
        return self.pkt_cfg.get_ops()

class DHCPC_ENTRY_INST():
    _giaddr_map = {}
    def __init__(self, mode, pkt_cfg):
        self.mode = mode
        self.pkt_cfg = pkt_cfg
        self.fixxid = False
        self.req_attr = {
                            'giaddr' : None,
                            'xid' : None,
                            'mac' : None,
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
        if self.req_attr['giaddr'] in DHCPC_ENTRY_INST._giaddr_map:
           return DHCPC_ENTRY_INST._giaddr_map[self.req_attr['giaddr']]
        else:
            DHCPC_ENTRY_INST._giaddr_map[self.req_attr['giaddr']] = randomMAC()
            return DHCPC_ENTRY_INST._giaddr_map[self.req_attr['giaddr']]

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
        if self.mode == 1:
            return self.gen_detail_pkt(self.pkt_cfg)

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
                        ("vendor_class_id", None),
                        "end"])

        bootp_pkt = BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], flags=0x8000)
        udp_header = UDP(sport=SRC_PORT, dport=DST_PORT)
        ip_header = IP(src = ZERO_IP, dst = BROADSTCAST_IP)
        eth_header = Ether(src = self.req_attr['mac'], dst=BROADSTCAST_MAC)

        if self.req_attr['giaddr'] != None:
            # DhcpcControlCenter.sup.add_dhcp_bind(self.req_attr['giaddr'], self.giaddr_mac)
            return Ether(src = self.giaddr_mac, dst=BROADSTCAST_MAC) / IP(src = self.req_attr['giaddr'], dst = BROADSTCAST_IP) / udp_header / \
            BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], giaddr = self.req_attr['giaddr'], flags=0x8000) \
            / dhcp_pkt

        return  eth_header / ip_header / udp_header / bootp_pkt / dhcp_pkt

    def set_options(self, ops):
        options = [
                    ("subnet_mask", ops[1]),
                    ("time_zone", int(ops[2]) if ops[2] else None),
                    ("router", ops[3]),
                    ("time_server", ops[4]),
                    ("IEN_name_server", ops[5]),
                    ("name_server", ops[6]),
                    ("log_server", ops[7]),
                    ("cookie_server", ops[8]),
                    ("lpr_server", ops[9]),
                    ("impress-servers", ops[10]),
                    ("resource-location-servers", ops[11]),
                    ("hostname", ops[12]),
                    ("boot-size", int(ops[13]) if ops[13] else None),
                    # ("dump_path", ops[14]),
                    # ("domain", ops[15]),
                    ("swap-server", ops[16]),
                    # ("root_disk_path", ops[17]),
                    # ("extensions-path", ops[18]),
                    ("ip-forwarding", int(ops[19]) if ops[19] else None),
                    ("non-local-source-routing", int(ops[20]) if ops[20] else None),
                    ("policy-filter", ops[21]),
                    ("max_dgram_reass_size", int(ops[22]) if ops[22] else None),
                    ("default_ttl", int(ops[23]) if ops[23] else None),
                    ("pmtu_timeout", int(ops[24]) if ops[24] else None),
                    ("path-mtu-plateau-table", int(ops[25]) if ops[25] else None),
                    ("interface-mtu", int(ops[26]) if ops[26] else None),
                    ("all-subnets-local", int(ops[27]) if ops[27] else None),
                    ("broadcast_address", ops[28]),
                    ("perform-mask-discovery", int(ops[29]) if ops[29] else None),
                    ("mask-supplier", int(ops[30]) if ops[30] else None),
                    ("router-discovery", int(ops[31]) if ops[31] else None),
                    ("router-solicitation-address", ops[32]),
                    ("static-routes", ops[33]),
                    ("trailer-encapsulation", int(ops[34]) if ops[34] else None),
                    ("arp_cache_timeout", int(ops[35]) if ops[35] else None),
                    ("ieee802-3-encapsulation", int(ops[36]) if ops[36] else None),
                    ("tcp_ttl", int(ops[37]) if ops[37] else None),
                    ("tcp_keepalive_interval", int(ops[38]) if ops[38] else None),
                    ("tcp_keepalive_garbage", int(ops[39]) if ops[39] else None),
                    ("NIS_domain", ops[40]),
                    ("NIS_server", ops[41]),
                    ("NTP_server", ops[42]),
                    # ("vendor_specific", ops[43]),
                    ("NetBIOS_server", ops[44]),
                    ("NetBIOS_dist_server", ops[45]),
                    ("NetBIOS_node_type", int(ops[46]) if ops[46] else None),
                    # ("netbios-scope", ops[47]),
                    ("font-servers", ops[48]),
                    ("x-display-manager", ops[49]),
                    ("requested_addr", ops[50]),
                    ("lease_time", int(ops[51]) if ops[51] else None),
                    ("dhcp-option-overload", int(ops[52]) if ops[52] else None),
                    ("message-type", ops[53]),
                    ("server_id", ops[54]),
                    ("param_req_list", [int(x) for x in ops[55].split(",")]),
                    # ("error_message", ops[56]),
                    ("max_dhcp_size", int(ops[57]) if ops[57] else None),
                    ("renewal_time", int(ops[58]) if ops[58] else None),
                    ("rebinding_time", int(ops[59]) if ops[59] else None),
                    ("vendor_class_id", ops[60]),
                    ("client_id", ops[61]),
                    # ("nwip-domain-name", ops[62]),
                    # ("NISplus_domain", ops[64]),
                    ("NISplus_server", ops[65]),
                    # ("tftp_server_name", ops[66]),
                    ("boot-file-name", ops[67]),
                    ("mobile-ip-home-agent", ops[68]),
                    ("SMTP_server", ops[69]),
                    ("POP3_server", ops[70]),
                    ("NNTP_server", ops[71]),
                    ("WWW_server", ops[72]),
                    ("Finger_server", ops[73]),
                    ("IRC_server", ops[74]),
                    ("StreetTalk_server", ops[75]),
                    ("StreetTalk_Dir_Assistance", ops[76]),
                    # ("user_class", ops[77]),
                    # ("slp_service_agent", ops[78]),
                    # ("slp_service_scope", ops[79]),
                    # ("client_FQDN", ops[81]),
                    # ("relay_agent_information", ops[82]),
                    ("nds-server", ops[85]),
                    ("nds-tree-name", ops[86]),
                    ("nds-context", ops[87]),
                    # ("bcms-controller-namesi", ops[88]),
                    # ("bcms-controller-address", ops[89]),
                    ("client-last-transaction-time", int(ops[91]) if ops[91] else None),
                    ("associated-ip", ops[92]),
                    # pxe_client_architecture ops[93]
                    # ("pxe_client_network_interface", ops[94]),
                    # ("pxe_client_machine_identifier", ops[97]),
                    ("uap-servers", ops[98]),
                    ("pcode", ops[100]),
                    ("tcode", ops[101]),
                    ("netinfo-server-address", ops[112]),
                    ("netinfo-server-tag", ops[113]),
                    ("default-url", ops[114]),
                    ("auto-config", int(ops[116]) if ops[116] else None),
                    ("name-service-search", int(ops[117]) if ops[117] else None),
                    # ("vendor_class", ops[118]),
                    ("subnet-selection", ops[124]),
                    # ("vendor_specific_information", ops[125]),
                    ("tftp_server_ip_address", ops[128]),
                    ("pana-agent", ops[136]),
                    # ("v4-lost", ops[137]),
                    ("capwap-ac-v4", ops[138]),
                    # ("sip_ua_service_domains", ops[141]),
                    # ("rdnss-selection", ops[146]),
                    ("tftp_server_address", ops[150]),
                    # ("v4-portparams", ops[159]),
                    ("v4-captive-portal", ops[160]),
                    ("mud-url", ops[161]),
                    # ("pxelinux_magic", ops[208]),
                    # ("pxelinux_configuration_file", ops[209]),
                    # ("pxelinux_path_prefix", ops[210]),
                    # ("pxelinux_reboot_time", ops[211]),
                    # ("option-6rd", ops[212]),
                    # ("v4-access-domain", ops[213]),
                    "end"
        ]

        re_options = list()
        for v in options:
            if (type(v) == tuple):
                if v[1] != None and v[1] != '':
                    re_options.append(v)
        re_options.append("end")
        return re_options

    def gen_detail_pkt(self, pkt_cfg:DHCPC_PKT_CFG):
        self.req_attr['mac'] = pkt_cfg.get_chaddr()
        self.req_attr['xid'] = pkt_cfg.get_xid()
        self.req_attr['chaddr'] = mac2str(self.req_attr['mac'])

        ops = pkt_cfg.get_ops()
        if (ops[53]):
            msgtype = ops[53]
        else:
            logger.debug("ERROR message-type")
            return None

        if (ops[55]):
            self.req_attr['req_list'] = [int(x) for x in ops[55].split(",")]

        max_dhcp_size = 576
        if (ops[57]):
            max_dhcp_size = int(ops[57])
        if (ops[12]):
            self.req_attr['hostname'] = ops[12]

        flags = 0x0
        if (pkt_cfg.get_flags() == "broadcast"):
            flags = 0x8000

        dhcp_pkt = DHCP(options=self.set_options(ops))
        

        bootp_pkt = BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], flags=flags)
        udp_header = UDP(sport=SRC_PORT, dport=DST_PORT)
        ip_header = IP(src = ZERO_IP, dst = BROADSTCAST_IP)
        eth_header = Ether(src = self.req_attr['mac'], dst=BROADSTCAST_MAC)

        if self.req_attr['giaddr'] != None:
            # DhcpcControlCenter.sup.add_dhcp_bind(self.req_attr['giaddr'], self.giaddr_mac)
            return Ether(src = self.giaddr_mac, dst=BROADSTCAST_MAC) / IP(src = self.req_attr['giaddr'], dst = BROADSTCAST_IP) / udp_header / \
            BOOTP(chaddr=self.req_attr['chaddr'], xid=self.req_attr['xid'], giaddr = self.req_attr['giaddr'], flags=0x8000) \
            / dhcp_pkt
        pkt = eth_header / ip_header / udp_header / bootp_pkt / dhcp_pkt
        return pkt

class DhcpcBindsEntryInfo():
    def __init__(self, ip, mac) -> None:
        self.ip = ip
        self.mac = mac

class DHCPC_ENTRY_FSM_MSG():
    def __init__(self, func) -> None:
        self.func = func

@acts_as_state_machine
class DHCPC_ENTRY_FSM():
    nty_userbind_gen_cb = None
    non_userbind_cb = None
    max_retrans_times = 3
    __entry_id = 0
    dhcpc_que = NonBlockingQueueSimpleFactory.create_nonblockingqueue("realize")

    INIT = State(initial=True)
    SELECTING = State()
    REQUESTING = State()
    BOUND = State()
    # [TODO]
    # RENEWING = State()
    # REBINDING = State()
    # INIT_REBOOT = State()
    # REBOOTING = State()

    fsm_start = Event(from_states=(INIT, SELECTING, REQUESTING), to_state=SELECTING)
    resend_discoverpkt = Event(from_states=SELECTING, to_state=SELECTING)
    fsm_select = Event(from_states=SELECTING, to_state=SELECTING)
    fsm_selected = Event(from_states=SELECTING, to_state=REQUESTING)
    resend_requestpkt = Event(from_states=REQUESTING, to_state=REQUESTING)
    fsm_noreply = Event(from_states=(SELECTING, REQUESTING, BOUND), to_state=INIT)
    fsm_bound = Event(from_states=REQUESTING, to_state=BOUND)
    fsm_admin_down = Event(from_states=(SELECTING, REQUESTING, BOUND), to_state=INIT)

    @after('fsm_admin_down')
    def _(self):
        logger.debug("admin down")
        self.clear_flag = True

    @after('fsm_noreply')
    def _(self):
        self.retrans_times = 0

    @after('fsm_start')
    def _(self):
        logger.debug("send a discover")
        self.retrans_times = 0
        self.gen_pkt = self.entry.gen_discover()
        DHCPC_ENTRY_FSM.dhcpc_retrans_check(self)
        sendp(self.gen_pkt, iface = conf.iface, verbose = False)
    @after('resend_discoverpkt')
    def _(self):
        self.retrans_times += 1
        if (self.retrans_times > DHCPC_ENTRY_FSM.max_retrans_times):
            self.fsm_start()
            return
        sendp(self.gen_pkt, iface = conf.iface, verbose = False)

    @after('fsm_select')
    def _(self):
        logger.debug("select a offer")
        self.fsm_selected()

    @after('resend_requestpkt')
    def _(self):
        self.retrans_times += 1
        if (self.retrans_times > DHCPC_ENTRY_FSM.max_retrans_times):
            self.fsm_start()
            return
        sendp(self.gen_pkt, iface = conf.iface, verbose = False)
    @after('fsm_selected')
    def _(self):
        logger.debug("send a request")
        self.retrans_times = 0
        self.entry.get_attr_by_dhcp(self.rc_pkt)
        self.gen_pkt = self.entry.gen_request()
        sendp(self.gen_pkt, iface = conf.iface, verbose = False)

    @before('fsm_bound')
    def _(self):
        logger.debug("recv ack")
        self.entry.get_attr_by_dhcp(self.rc_pkt)
        self.entry.req_attr['xid'] = 0x0
        # if (sth is wrong):
            # [TODO]
    @after('fsm_bound')
    def _(self):
        logger.debug("do bound")
        DHCPC_ENTRY_FSM.nty_userbind_gen_cb(self.entry)
        DHCPC_ENTRY_FSM.dhcpc_retrans_check(self)

    def __init__(self, mode, pkt_cfg) -> None:
        DHCPC_ENTRY_FSM.__entry_id += 1
        self.id = DHCPC_ENTRY_FSM.__entry_id
        self.entry = DHCPC_ENTRY_INST(mode, pkt_cfg)
        self.rc_pkt = None
        self.gen_pkt = None
        self.retrans_times = 0
        self.clear_flag = False

    def set_nty_userbind_gen_cb(cb):
        DHCPC_ENTRY_FSM.nty_userbind_gen_cb = cb
    def set_dhcpc_retrans_check(cb):
        DHCPC_ENTRY_FSM.dhcpc_retrans_check = cb

    def get_current_state(self):
        return self.current_state

    def start(self):
        if (self.get_current_state() == "BOUND"):
            return
        self.fsm_start()
    def stop(self):
        DHCPC_ENTRY_FSM.join_event_queue(self.fsm_admin_down)

    def bound_show(self):
        if (self.get_current_state() == "BOUND"):
            logger.debug("local bound, id:%d :ip(%s), mac(%s), server(%s)\n" % (self.id, self.entry.get_attr['get_ip'], self.entry.req_attr['mac'], self.entry.get_attr['server_id']))

    # thread safe
    def join_event_queue(func):
        DHCPC_ENTRY_FSM.dhcpc_que.put(DHCPC_ENTRY_FSM_MSG(func))
    def fsm_event_queue_process():
        DHCPC_ENTRY_FSM.dhcpc_que.foreach(DHCPC_ENTRY_FSM.deal_fsm_event_cb)
        PseudoThread.async_run_later_event(DHCPC_ENTRY_FSM.fsm_event_queue_process, 0.1)
    def get_fsm_event():
        return DHCPC_ENTRY_FSM.dhcpc_que.get()
    def deal_fsm_event_cb(msg:DHCPC_ENTRY_FSM_MSG):
        if msg and msg.func:
            try:
                # [TODO] if (self.clear_flag): return
                msg.func()
            except InvalidStateTransition as err:
                pass
            


