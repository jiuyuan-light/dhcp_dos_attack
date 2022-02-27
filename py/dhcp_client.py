# -*- coding:utf-8 -*-
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import *
from dhcp_client_fsm import *
from dhcp_sup import PseudoThread

import argparse
import logging
from scapy.config import conf

conf.logLevel = logging.ERROR

logger = logging.getLogger('dhcp_client')
logging.basicConfig(format='%(levelname)s:%(funcName)s:%(message)s', level = logging.WARNING)

def dhcp_sniff_pkt_cb(packet):
    if (packet[BOOTP].op == 2):
        for client in M_DHCP_CLIENT_CENTER.get_dhcpc_list():
            entry = client.entry
            if (client.get_dhcpc_state() == DHCPS_BIND):
                continue
            if (entry.req_attr['xid'] == packet[BOOTP].xid and entry.req_attr['chaddr'] == packet[BOOTP].chaddr[:len(entry.req_attr['chaddr'])]):
                # logger.debug('SRC[%s] DST[%s] [%s]' % (packet[IP].src, packet[IP].dst, packet[BOOTP].yiaddr))
                for mess in packet["DHCP options"].options:
                    if (len(mess) == 2 and mess[0] == 'message-type'):
                        client.rc_pkt = packet
                        if (mess[1] == 2): #offer
                            client.sync_fsm_event(DH_Recv_Offer)
                            break
                        elif (mess[1] == 5): #ack
                            client.sync_fsm_event(DH_Recv_Ack)
                            break
                        else:
                            logger.debug("###2", client.get_dhcpc_state())
            else:
                #logger.debug("not except packet, ignore")
                pass

def dhcp_re_trans():
    for client in M_DHCP_CLIENT_CENTER.clients_re_trans_list:
        client.sync_fsm_event(DH_ReSend_Packet)
    PseudoThread.async_run_later_event(dhcp_re_trans, DHCPC_PKT_RETRANS_TIME)

def show_state():
    logger.debug("all client count:%d bound count:%d , ..." % (M_DHCP_CLIENT_CENTER.get_dhcpc_count(), M_DHCP_CLIENT_CENTER.get_dhcpc_bound_count()))
    if (M_DHCP_CLIENT_CENTER.get_dhcpc_count() == M_DHCP_CLIENT_CENTER.get_dhcpc_bound_count()):
        for client in M_DHCP_CLIENT_CENTER.get_dhcpc_list():
            client.bound_show()
        return
    PseudoThread.async_run_later_event(show_state, 3)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('interface', nargs='?', help='interface to configure with DHCP')
    parser.add_argument('-n', '--nums', help='client nums')
    parser.add_argument('-d', '--debug', help='Set logging level to debug', action='store_true')
    parser.add_argument('-f', '--file', help='load config file')

    logger.setLevel(logging.DEBUG)
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.interface is None:
        logger.error('DHCP related interfaces must be specified')
        args.interface = '以太网'
        # exit(1)
    if args.nums is None:
        logger.error('not input nums, default 1')
        args.nums = 1

    if args.file is None:
        logger.info('no cfg file')
    
    # do not put interfaces in promiscuous mode
    conf.sniff_promisc = conf.promisc = 0
    #conf.checkIPaddr = 1
    conf.use_pcap = True
    conf.iface = args.interface

    logger.debug('args %s', args)
    
    dhcp_recv_pkt_thread = AsyncSniffer(lfilter=lambda pkt : DHCP in pkt, iface = conf.iface, prn = dhcp_sniff_pkt_cb)
    dhcp_recv_pkt_thread.start()
    time.sleep(1)

    logger.debug("########################[nice weather today]########################")
    
    center = M_DHCP_CLIENT_CENTER(int(args.nums), args.file)
    center.start()

    PseudoThread.async_run_now(show_state)
    PseudoThread.async_run_later_event(dhcp_re_trans, DHCPC_PKT_RETRANS_TIME)
    
    #主线程不退出
    PseudoThread.run_forever()

if __name__ == "__main__":
    main()