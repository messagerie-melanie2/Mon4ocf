#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Ces fichiers Mon4ocf ont été édéveloppés pour réaliser des scripts
s'interfaçant les scripts PyOcfScripts.

Mon4ocf Copyright © 2017  PNE Annuaire et Messagerie/MEDDE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

# data line is 
# for suspending: 0:timestamp:suspended time:suspend_advanced_mon_type:msgend
# for activating: 1:timestamp:::msgend

import sys, os, time, argparse, socket, syslog

msgend='state-end'
allowed_types=['search', 'status']

def print_or_log(withlog, msg, loglvl=syslog.LOG_INFO):
    if withlog:
        syslog.syslog(loglvl, msg)
    else:
        if loglvl == syslog.LOG_WARNING or loglvl == syslog.LOG_ERR:
            sys.stderr.write('{}\n'.format(msg))
        else:
            sys.stdout.write('{}\n'.format(msg))

def send_data(socketpath, data, quiet, withlog):
    ret = False
    sockdir = os.path.dirname(socketpath)
    if os.path.isdir(sockdir):
        try:
            os.remove(socketpath)
        except OSError:
            if os.path.exists(socketpath):
                print_or_log(withlog, 'Can not remove {}'.format(socketpath), loglvl=syslog.LOG_ERR)
                os._exit(1)
    else:
        try:
            os.makedirs(sockdir, 0755)
        except:
            print_or_log(withlog, 'Can not create {}'.format(sockdir), loglvl=syslog.LOG_ERR)
            os._exit(1)
            
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socketpath)
        sock.listen(1)
    except:
        print_or_log(withlog, 'Can not initialize connection to {}'.format(socketpath), loglvl=syslog.LOG_ERR)
        sys.exit(1)
    

    if not quiet: print_or_log(withlog, 'send_data: waiting connection.')
    try:
        conn, addr = sock.accept()
    except:
        print_or_log(withlog, 'send_data: problem during sock.accept.', loglvl=syslog.LOG_ERR)
        sys.exit(1)
    
    while True:
        if not quiet: print_or_log(withlog, 'send_data: waiting for reception.')
        try:
            rdata = conn.recv(6)
            if not quiet: print_or_log(withlog, 'send_data: message received {}.'.format(rdata))
        except:
            print_or_log(withlog, 'Can not read data from {}.'.format(socketpath))
            break
        if rdata and rdata == 'state':
            #sdata = '{}:{}:status-end'.format(etat, time.time())
            if not quiet: print_or_log(withlog, 'send_data: sending {}.'.format(data))
            try:
                conn.sendall(data)
            except:
                break
            else:
                try:
                    rdata = conn.recv(12)
                    if not quiet: print_or_log(withlog, 'send_data: message received {}.'.format(rdata))
                except:
                    print_or_log(withlog, 'Can not read return data from {}.'.format(socketpath), loglvl=syslog.LOG_ERR)
                    break
                if rdata and rdata == msgend:
                    if not quiet: print_or_log(withlog, 'send_data: cluster does not want to send result {}.'.format(rdata))
                    ret = True
                    break
                if rdata and rdata == 'wait-result':
                    try:
                        rdata = conn.recv(16)
                        if not quiet: print_or_log(withlog, 'send_data: message received {}.'.format(rdata))
                    except:
                        print_or_log(withlog, 'Can not read return information from the cluster from {}.'.format(socketpath), loglvl=syslog.LOG_ERR)
                        break
                    if rdata:
                        rdatatab = rdata.split(':')
                        if rdatatab[1] != msgend and (rdatatab[0] == 'True' or rdatatab[0] == 'False'):
                            print_or_log(withlog, 'return information from the cluster have a bad format.', loglvl=syslog.LOG_ERR)
                            break
                        else:
                            if rdatatab[0] == 'True':
                                ret = True
        else:
            if not quiet: print_or_log(withlog, 'send_data: no more data.')
            break

    try:
        conn.close()
    except:
        print_or_log(withlog, 'send_data: problem when closing connexion.', loglvl=syslog.LOG_ERR)
        
    return ret

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Suspend or reactivate the advanced monitoring of slapd\'s cluster service')
    parser.add_argument('time', help='suspend the advanced monitoring of slapd\'s cluster service for this time (in seconds). zero or less reactivate the monitoring', type=int)
    parser.add_argument('-s', '--socket', help='Socket path (default=/var/run/mon-charge-ldap/socket/suspendmon)', metavar='socket', default='/var/run/mon-charge-ldap/socket/suspendmon')
    parser.add_argument('-t', '--types', help='type of suspended monitoring. Allowed types: {}, Default : search,status'.format(allowed_types), metavar='TYPE', default='search,status')
    parser.add_argument('-q', '--quiet', help='quiet run', action='store_true')
    parser.add_argument('-l', '--log', help='log in to user.log/warn/err', action='store_true')
    args = parser.parse_args()
    
    syslog.openlog(logoption=syslog.LOG_PID, facility=syslog.LOG_USER)
    
    if not set(allowed_types) >= set(args.types.rstrip(',').split(',')):
        print_or_log(withlog, 'This types are not allowed', loglvl=syslog.LOG_ERR)
        sys.exit(1)
    
    nowts = time.time()
    
    if args.time > 0:
        if not args.quiet: print_or_log(args.log, 'Suspending the advanced monitoring of slapd\'s cluster service for {} seconds.'.format(args.time))
        data = '0:{}:{}:{}:{}'.format(nowts, args.time, args.types, msgend)
    else:
        if not args.quiet: print_or_log(args.log, 'Reactivating the advanced monitoring of slapd\'s cluster service.')
        data = '1:{}:::{}'.format(nowts, msgend)

    if send_data(args.socket, data, args.quiet, args.log):
        sys.exit(0)
    else:
        sys.exit(1)
