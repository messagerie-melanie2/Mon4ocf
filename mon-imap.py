#! /usr/bin/env python
# -*- coding: utf-8 -*-

'''
Ces fichiers Mon4ocf ont été édéveloppés pour réaliser des scripts
s'interfaçant les scripts PyOcfScripts.

Mon4ocf Copyright © 2021  GMCD/MTE

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

import sys
import argparse
import psutil
import syslog
import os
import time
import imaplib
import poplib
import smtplib
from mon4ocf import Mon4ocfError, Mon4ocf


################################################################################
class MonImap(Mon4ocf):
    ########################################
    def __init__(self):
        args = self.parse_all_args()
        self.cyrusbinfile = args.cyrusbinfile
        self.numberfailsimap = args.numberfailsimap
        self.numberfailsimaps = args.numberfailsimaps
        self.numberfailspop3 = args.numberfailspop3
        self.numberfailspop3s = args.numberfailspop3s
        self.numberfailslmtp = args.numberfailslmtp
        self.numberfailsglobal = args.numberfailsglobal
        self.noimap = args.noimap
        self.noimaps = args.noimaps
        self.nopop3 = args.nopop3
        self.nopop3s = args.nopop3s
        self.nolmtp = args.nolmtp
        self.interval = args.interval
        self.start_delay = args.start_delay
        self.lmtpsocket = args.lmtpsocket
        super(self.__class__, self).__init__("monitor", "send_data", args.socket, args.debug)

        syslog.syslog(syslog.LOG_INFO,  \
            'monitor: cyrusbinfile={}, numberfailsimap={}, numberfailsimaps={}, numberfailsglobal={}, noimap={}, noimaps={}, interval={}, start_delay={}, socket={}'.format( \
                self.cyrusbinfile, self.numberfailsimap, self.numberfailsimaps, self.numberfailsglobal, self.noimap, self.noimaps, self.interval, self.start_delay, self.socket))

    ########################################
    def parse_all_args(self):
        parser = argparse.ArgumentParser (description="monitor imap connexion")
        parser.add_argument('-c', '--cyrusbinfile', help='cyrus master binary file',  metavar='CYRUS_BINFILE', default='/usr/sbin/cyrmaster')
        parser.add_argument('--numberfailsimap', help='number of fails on imap before error', metavar='NUMBER_FAILS_IMAP', default=10, type=int)
        parser.add_argument('--numberfailsimaps', help='number of fails on imaps before error', metavar='NUMBER_FAILS_IMAPS', default=10, type=int)
        parser.add_argument('--numberfailspop3', help='number of fails on pop3 before error', metavar='NUMBER_FAILS_POP3', default=10, type=int)
        parser.add_argument('--numberfailspop3s', help='number of fails on pop3s before error', metavar='NUMBER_FAILS_POP3S', default=10, type=int)
        parser.add_argument('--numberfailslmtp', help='number of fails on lmtp before error', metavar='NUMBER_FAILS_LMTP', default=10, type=int)
        parser.add_argument('--numberfailsglobal', help='number of global fails before error', metavar='NUMBER_FAILS_GLOBAL', default=50, type=int)
        parser.add_argument('--noimap', help='Don\'t monitor imap', action='store_true')
        parser.add_argument('--noimaps', help='Don\'t monitor imaps', action='store_true')
        parser.add_argument('--nopop3', help='Don\'t monitor pop3', action='store_true')
        parser.add_argument('--nopop3s', help='Don\'t monitor pop3s', action='store_true')
        parser.add_argument('--nolmtp', help='Don\'t monitor lmtp', action='store_true')
        parser.add_argument('-s', '--socket', help='socket for writing result. defaut=/var/run/moncyrusmupdate/socket/mon', metavar='SOCKET', default='/var/run/moncyrusmupdate/socket/mon')
        parser.add_argument('-i', '--interval', help='inteval in secondes in each monitoring. defaut=10',  metavar='INTERVAL', default=10, type=int)
        parser.add_argument('--start_delay', help='delay in seconds before beginnig monitoring', metavar='DELAY', default=120, type=int)
        parser.add_argument('--lmtpsocket', help='socket for lmtp. defaut=/var/run/cyrus/socket/lmtp', metavar='LTMP_SOCKET', default='/var/run/cyrus/socket/lmtp')
        parser.add_argument('-d', '--debug', help='mode debug on', action='store_true')
        return parser.parse_args()

    ########################################
    def monitor(self):
        '''
        etat=0 => OK
        etat=1 => KO
        '''
        nbfailsimap=0
        nbfailsimaps=0
        nbfailspop3=0
        nbfailspop3s=0
        nbfailslmtp=0
        nbfailsglobal=0
        while True:
            etat='0'
            try:
                cyrus_pid = self.get_pids(self.cyrusbinfile, raise_ppid_not_ok=True)[0]
                if self.debug: syslog.syslog(syslog.LOG_DEBUG, 'monitor thread : cyrus_pid={}'.format(cyrus_pid))
                is_cyrus_just_start = self.is_process_just_start_pid(cyrus_pid, self.start_delay)
            except:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : {} not started or not started correctly'.format(self.cyrusbinfile))
            else:
                if is_cyrus_just_start:
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : {} just start. Waiting for beginnig monitoring'.format(self.cyrusbinfile))
                else:
                    try:
                        if not self.noimap: imaplib.IMAP4('127.0.0.1', '143')
                    except:
                        nbfailsimap+=1
                        nbfailsglobal+=1
                        syslog.syslog(syslog.LOG_WARNING, \
                            'monitor thread : imap connexion failed. Number of failed imap connexion: {}. Number of global failed: {}'.format(nbfailsimap, nbfailsglobal))
                    else:
                        nbfailsimap=0
                        nbfailsglobal=nbfailsimaps+nbfailspop3+nbfailspop3s+nbfailslmtp
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG, \
                            'monitor thread : imap connexion succes. Number of failed imap connexion: {}. Number of global failed: {}'.format(nbfailsimap, nbfailsglobal))
                    
                    try:
                        if not self.noimaps: imaplib.IMAP4_SSL('127.0.0.1', '993')
                    except:
                        nbfailsimaps+=1
                        nbfailsglobal+=1
                        syslog.syslog(syslog.LOG_WARNING, \
                            'monitor thread : imaps connexion failed. Number of failed imaps connexion: {}. Number of global failed: {}'.format(nbfailsimaps, nbfailsglobal))
                    else:       
                        nbfailsimaps=0
                        nbfailsglobal=nbfailsimap+nbfailspop3+nbfailspop3s+nbfailslmtp
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG, \
                            'monitor thread : imaps connexion success. Number of failed imaps connexion: {}. Number of global failed: {}'.format(nbfailsimaps, nbfailsglobal))

                    try:
                        if not self.nopop3: poplib.POP3('127.0.0.1', '110')
                    except:
                        nbfailspop3+=1
                        nbfailsglobal+=1
                        syslog.syslog(syslog.LOG_WARNING, \
                            'monitor thread : pop3 connexion failed. Number of failed pop3 connexion: {}. Number of global failed: {}'.format(nbfailspop3, nbfailsglobal))
                    else:
                        nbfailspop3=0
                        nbfailsglobal=nbfailsimap+nbfailsimaps+nbfailspop3s+nbfailslmtp
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG, \
                            'monitor thread : pop3 connexion succes. Number of failed pop3 connexion: {}. Number of global failed: {}'.format(nbfailspop3, nbfailsglobal))
                    
                    try:
                        if not self.nopop3s: poplib.POP3_SSL('127.0.0.1', '995')
                    except:
                        nbfailspop3s+=1
                        nbfailsglobal+=1
                        syslog.syslog(syslog.LOG_WARNING, \
                            'monitor thread : pop3s connexion failed. Number of failed pop3s connexion: {}. Number of global failed: {}'.format(nbfailspop3s, nbfailsglobal))
                    else:
                        nbfailspop3s=0
                        nbfailsglobal=nbfailsimap+nbfailsimaps+nbfailspop3+nbfailslmtp
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG, \
                            'monitor thread : pop3s connexion succes. Number of failed pop3s connexion: {}. Number of global failed: {}'.format(nbfailspop3s, nbfailsglobal))

                    try:
                        if not self.nolmtp: smtplib.LMTP(host=self.lmtpsocket)
                    except:
                        nbfailslmtp+=1
                        nbfailsglobal+=1
                        syslog.syslog(syslog.LOG_WARNING, \
                            'monitor thread : lmtp connexion failed. Number of failed lmtp connexion: {}. Number of global failed: {}'.format(nbfailslmtp, nbfailsglobal))
                    else:
                        nbfailslmtp=0
                        nbfailsglobal=nbfailsimap+nbfailsimaps+nbfailspop3+nbfailspop3s
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG, \
                            'monitor thread : lmtp connexion succes. Number of failed lmtp connexion: {}. Number of global failed: {}'.format(nbfailslmtp, nbfailsglobal))

                    if nbfailsimap >= self.numberfailsimap or \
                        nbfailsimaps >= self.numberfailsimaps or \
                        nbfailspop3 >= self.numberfailspop3 or \
                        nbfailspop3s >= self.numberfailspop3s or \
                        nbfailslmtp >= self.numberfailslmtp or \
                        nbfailsglobal >= self.numberfailsglobal:
                        etat='1'
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : Sending state: {}'.format(etat))
                self.put_in_queue(etat)
            finally: 
                # sleep
                time.sleep(self.interval)

################################################################################
if __name__ == '__main__':
    if os.getuid() != 0:
        print ('you must be root')
        sys.exit(1)
    
    mi = MonImap()
    mi.run_thread()