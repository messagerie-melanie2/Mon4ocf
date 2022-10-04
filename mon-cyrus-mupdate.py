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

import sys,  argparse,  psutil,  syslog,  os,  time
from mon4ocf import Mon4ocfError, Mon4ocf


################################################################################
class MonCyrusMupdate(Mon4ocf):
    ########################################
    def __init__(self):
        args = self.parse_all_args()
        self.cyrusbinfile = args.cyrusbinfile
        self.mupdatebinfile = args.mupdatebinfile
        self.numbermupdate = args.numbermupdate
        self.interval = args.interval
        self.start_delay = args.start_delay
        super(self.__class__, self).__init__("monitor", "send_data", args.socket, args.debug)
        
        syslog.syslog(syslog.LOG_INFO,  'monitor: cyrusbinfile={}, mupdatebinfile={}, numbermupdate={}, interval={}, start_delay={}, socket={}'.format(self.cyrusbinfile, self.mupdatebinfile, self.numbermupdate,  self.interval,  self.start_delay, self.socket))

    ########################################
    def parse_all_args(self):
        parser = argparse.ArgumentParser (description="monitor cpu load for a process")
        parser.add_argument('-c', '--cyrusbinfile', help='cyrus master binary file',  metavar='CYRUS_BINFILE', default='/usr/sbin/cyrmaster')
        parser.add_argument('-m', '--mupdatebinfile', help='cyrus mupdate binary file',  metavar='MUPDATE_BINFILE', default='mupdate')
        parser.add_argument('-n', '--numbermupdate', help='number of processes cyrus mupdate',  metavar='NUMBER_MUPDATE', default=2, type=int)
        parser.add_argument('-s', '--socket', help='socket for writing result. defaut=/var/run/moncyrusmupdate/socket/mon',  metavar='SOCKET',  default='/var/run/moncyrusmupdate/socket/mon')
        parser.add_argument('-i', '--interval', help='inteval in secondes in each monitoring. defaut=1',  metavar='INTERVAL',  default=1,  type=int)
        parser.add_argument('--start_delay', help='delay in seconds before beginnig monitoring', metavar='DELAY', default=300, type=int)
        parser.add_argument('-d', '--debug', help='mode debug on',  action='store_true')
        return parser.parse_args()

    ########################################
    def monitor(self):
        '''
        etat=0 => OK
        etat=1 => KO
        '''
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
                        mupdate_pids = self.get_pids(self.mupdatebinfile, ppid=cyrus_pid, raise_ppid_not_ok=True, number_of_process=self.numbermupdate)
                    except:
                        syslog.syslog(syslog.LOG_WARNING, 'failed to detect {} mupdate processes with ppid {}'.format(self.numbermupdate, cyrus_pid))
                        etat='1'
                    else:
                        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : {} mupdate found: {}'.format(self.numbermupdate, mupdate_pids))
                self.put_in_queue(etat)
            finally:
                # sleep
                time.sleep(self.interval)

################################################################################
if __name__ == '__main__':
    if os.getuid() != 0:
        print ('you must be root')
        sys.exit(1)
    
    mcl = MonCyrusMupdate()
    mcl.run_thread()