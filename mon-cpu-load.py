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
class MonChargeLdapma(Mon4ocf):
    ########################################
    def __init__(self):
        args = self.parse_all_args()
        self.maxload = args.maxload
        self.nbmon = args.nbmon
        self.interval = args.interval
        self.binfile = args.binfile
        super(self.__class__, self).__init__("monitor", "send_data", args.socket, args.debug)
        
        syslog.syslog(syslog.LOG_INFO,  'monitor: maxload={}, nbmon={}, interval={}, binfile={}, socket={}'.format(self.maxload, self.nbmon, self.interval,  self.binfile,  self.socket))

    ########################################
    def parse_all_args(self):
        parser = argparse.ArgumentParser (description="monitor cpu load for a process")
        parser.add_argument('-m', '--maxload', help='max load authorized. defaul=500', action='store', metavar='CHARGE', default='500',  type=int)
        parser.add_argument('-n', '--nbmon', help='number of point to calculate avergae load. defaut=1800',  metavar='NB_MON',  default='1800',  type=int)
        parser.add_argument('-i', '--interval', help='inteval in secondes in each monitoring. defaut=1',  metavar='INTERVAL',  default='1',  type=int)
        parser.add_argument('-b', '--binfile', help='openldap binary file',  metavar='BINFILE', required=True)
        parser.add_argument('-s', '--socket', help='socket for writing result. defaut=/var/run/moncharge/socket/mon',  metavar='SOCKET',  default='/var/run/moncharge/socket/mon')
        parser.add_argument('-d', '--debug', help='mode debug on',  action='store_true')
        return parser.parse_args()

    ########################################
    def addition(self, x, y): return x+y

    ########################################
    def init_pid_stats(self): return (None, [])

    ########################################
    def monitor(self):
        '''
        etat=0 => OK
        etat=1 => KO
        '''
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : start')
        pid, stats = self.init_pid_stats()
        i=0
        while True:
            etat='0'
            if not pid or (pid and not psutil.pid_exists(pid)):
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor: pid does not exist')
                pid = None
                while not pid:
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor: waiting for processus start')
                    try:
                        pid = self.get_pid(self.binfile)
                    except:
                        pass
                    finally:
                        time.sleep(1)
                    
                syslog.syslog(syslog.LOG_INFO,  'monitor: pid={}'.format(pid))
                try:
                    p = psutil.Process(pid)
                except:
                    syslog.syslog(syslog.LOG_WARNING,  'monitor: problem while using pid={}'.format(pid))
                    pid = None
                    
                stats=[]
                self.put_in_queue(etat)
                i=0
            else:
                try:
                    cpupc = p.get_cpu_percent()
                except:
                    syslog.syslog(syslog.LOG_WARNING,  'monitor: problem while using pid={} in get_cpu_percent'.format(pid))
                    pid,  stats = self.init_pid_stats()
                    self.put_in_queue(etat)
                else:
                    if len(stats) < self.nbmon:
                        try:
                            stats.append(cpupc)
                        except:
                            syslog.syslog(syslog.LOG_WARNING,  'monitor: problem while appending value={} to stats'.format(cpupc))
                            
                        self.put_in_queue(etat)
                    else:
                        try:
                            stats[i] = cpupc
                        except:
                            syslog.syslog(syslog.LOG_WARNING,  'monitor: problem while modifying stats {} (stats len={}) with value={}'.format(i,  len(stats),  cpupc))
                        
                        i=i+1 if i<self.nbmon-1 else 0
                        
                        try:
                            moy = reduce(self.addition, stats, 0)/self.nbmon
                        except:
                             syslog.syslog(syslog.LOG_WARNING,  'monitor: problem when calulate averaging')
                        else:
                            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'analyse: moyenne {}'.format(moy))
                            if moy >= self.maxload:
                                syslog.syslog(syslog.LOG_ERR,  'stat: load={} > maxload={}'.format(moy,  self.maxload))
                                etat='1'
                            else:
                                etat='0'
                        self.put_in_queue(etat)
                
            time.sleep(self.interval)

################################################################################
if __name__ == '__main__':
    if os.getuid() != 0:
        print ('you must be root')
        sys.exit(1)
    
    mcl = MonChargeLdapma()
    mcl.run_thread()
    