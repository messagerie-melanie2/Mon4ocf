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

import argparse, configparser, re, syslog, time, os, sys, collections
from threading import Thread
from mon4ocf import Mon4ocfError, Mon4ocf

################################################################################
class MonLogRule(object):
    ########################################
    def __init__(self, rulename, rerule, nbmaxlog, duration):
        self.rulename = rulename
        self.rerule = rerule
        self.nbmaxlog = nbmaxlog
        self.duration = duration
        self.recompile = re.compile(rerule)
        self.timelogfound = collections.deque(maxlen=self.nbmaxlog)
    
    ########################################
    def print_all_infos(self):
        print('\trulename={}, rerule={}, nbmaxlog={}, duration={}, recompile={}'.format(self.rulename, self.rerule, self.nbmaxlog, self.duration, self.recompile))

    ########################################
    def clean_timelogfound(self, clean_before_time):
        #while True:
        for i in range(self.timelogfound.maxlen):
            if self.timelogfound and self.timelogfound[0] < clean_before_time:
                self.timelogfound.popleft()
            else:
                break
    ########################################
    def add_time(self, time):
        self.timelogfound.append(time)
        print('timelogfound: {}'.format(self.timelogfound))
        
    ########################################
    def get_nb_found(self):
        print('timelogfound: {}, NB VALUE: {}'.format(self.timelogfound, len(self.timelogfound)))
        return len(self.timelogfound)


################################################################################
class MonLogFileInfo(object):
    ########################################
    def __init__(self, path):
        self.logpath = path
        self.reload = None
        self.rules = []
        self.inode = self.set_inode()
        self.fo = None
        self.open_file_and_seek_end()
        
    ########################################
    def add_rule_infos(self, rulename, re, nbmaxlog, duration):
        self.rules.append(MonLogRule(rulename, re, nbmaxlog, duration))
        
    ########################################
    def add_rule(self, rule):
        self.rules.append(rule)
        
    ########################################
    def print_all_infos(self):
        print('logfile={}, inode={}, fo={}, reload={}'.format(self.logpath, self.inode, self.fo, self.reload))
        for x in self.rules:
            x.print_all_infos()
        
    ########################################
    def open_file_and_seek_end(self):
        try:
            self.fo = open(self.logpath, 'r')
            self.fo.seek(0,2)
        except:
            syslog.syslog(syslog.LOG_ERR, 'Can\'t open file {}'.format(self.logpath))
            raise # TODO

    ########################################
    def set_inode(self):
        try:
            self.inode = os.stat(self.logpath).st_ino
        except:
            syslog.syslog(syslog.LOG_ERR, 'Can\'t get inode of {}'.format(self.logpath))

    #######################################
    def close_file(self):
        try:
            if self.fo: self.fo.close()
        except:
            pass # TODO ?

    ########################################
    def __del__(self):
        self.close_file()


################################################################################
class MonLog(Mon4ocf):
    ########################################
    def __init__(self, configfile):
        self.logfilesrules = collections.OrderedDict()
        
        try:
            conffile = configparser.ConfigParser()
            conffile.read(args.configfile)
            
            logfiles = conffile.get('DEFAULT', 'logfile', fallback='syslog').rstrip(',').split(',')
            self.debug = conffile.getboolean('DEFAULT', 'debug', fallback=False)
            socket = conffile.get('DEFAULT', 'socket', fallback='/var/run/monlog/monlog')
            
            self.read_all_logfiles_config(conffile, logfiles)
            self.print_all_rules()
        except Exception as err:
            self.log_and_print('Error in configuration file : aborting !')
            self.log_and_print('{}'.format(err))
        super(self.__class__, self).__init__("monitor", "send_data", socket, self.debug)
    
    ########################################
    def read_all_logfiles_config(self, configfile, logfiles):
        for logname in logfiles:
            try:
                lfpath = configfile.get(logname, 'path')
                self.logfilesrules[logname] = MonLogFileInfo(lfpath)
                self.logfilesrules[logname].reload = configfile.getboolean(logname, 'reloadfile', fallback=True)
            except Exception as err:
                self.log_and_print('{}'.format(err))
                sys.exit(1)
            r=1
            while True:
                try:
                    self.log_and_print('trying to read rulename {} for {}'.format(r, logname))
                    rulename = configfile.get(logname, str(r))
                    self.logfilesrules[logname].add_rule(self.read_rule(configfile, rulename))
                    r+=1
                except:
                    self.log_and_print('No more rule for {}'.format(logname))
                    break
            if r == 0:
                self.log_and_print('No rule define for {}'.format(logname))
                sys.exit(1)
    
    ########################################
    def read_rule(self, configfile, rulename):
        try:
            rerule = configfile.get(rulename, 're')
            nbmaxlog = configfile.getint(rulename, 'nbmaxlog', fallback=10)
            duration = configfile.getint(rulename, 'duration', fallback=60)
            newrule = MonLogRule(rulename, rerule, nbmaxlog, duration)
        except Exception as err:
            self.log_and_print('No rule information for {}'.format(rulename))
            self.log_and_print('{}'.format(err))
            sys.exit(1)
        return newrule
    
    ########################################
    def print_all_rules(self):
        if self.debug:
            for x in self.logfilesrules:
                print('logfile = {}'.format(x))
                self.logfilesrules[x].print_all_infos()
                
    ########################################
    def follow_logfile(self, logfileinfo):
        logfileinfo.fo.seek(0,2)
        while True:
            ino = os.stat(logfileinfo.logpath).st_ino
            if ino != logfileinfo.inode:
                syslog.syslog(syslog.LOG_INFO, 'For file {}, inode has changed.'.format(logfileinfo.logpath))
                logfileinfo.fo.close()
                logfileinfo.open_file_and_seek_end() # TODO try/except ?
                logfileinfo.inode = ino
            line = logfileinfo.fo.readline()
            if not line:
                time.sleep(0.1)
                continue
            yield line
    
    ########################################
    def read_logfile(self, threadname, logfileinfo):
        '''
        etat=0 => OK
        etat=1 => KO
        Adding entry to the queue only if the queue is empty because only the last value is send to the socket
        '''
        for line in self.follow_logfile(logfileinfo):
            for rule in logfileinfo.rules:
                if rule.recompile.search(line):
                    if self.debug: syslog.syslog(syslog.LOG_INFO, '{}: {} found'.format(threadname, rule.rerule))
                    newtime = time.time()
                    rule.add_time(newtime)
                    rule.clean_timelogfound(newtime-rule.duration)
                    if rule.get_nb_found() == rule.nbmaxlog:
                        syslog.syslog(syslog.LOG_INFO, '{}: max value {} is reached, queuing : 1 (not working)'.format(threadname, rule.nbmaxlog))
                        self.put_in_queue('1')
                    elif self.is_queue_empty():
                        if self.debug: syslog.syslog(syslog.LOG_INFO, '{}: queuing : 0 (working)'.format(threadname))
                        self.put_in_queue('0')
                elif self.is_queue_empty():
                    if self.debug: syslog.syslog(syslog.LOG_INFO, '{}: queuing : 0 (working)'.format(threadname))
                    self.put_in_queue('0')

    ########################################
    def monitor(self):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : start')
        logthread = {}
        for logname in self.logfilesrules:
            logthread[logname] = Thread(target=self.read_logfile, args=(logname, self.logfilesrules[logname]))
            logthread[logname].daemon = True
        
        while True:
            for logname in self.logfilesrules:
                if not logthread[logname].is_alive():
                    syslog.syslog(syslog.LOG_INFO, 'Starting {} thread'.format(logname))
                    logthread[logname].start()
            time.sleep(5)


################################################################################
if __name__ == '__main__':
    parser = argparse.ArgumentParser (description='Monitor log.')
    parser.add_argument ('configfile', help='configuration file')
    args = parser.parse_args()
    
    MonLog(args.configfile).run_thread()