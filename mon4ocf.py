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

import os, time, socket, syslog, psutil, ldap, sys, pylibmc, random, signal
from Queue import Queue
from threading import Thread

################################################################################
class Mon4ocfError(Exception):
    def __init__ (self, value,  strval):
        self.err = value
        self.strerror = strval

################################################################################
class Mon4ocf(object):
    ########################################
    def __init__(self, monitor_threadname, senddata_threadname, socket, debug, syslog_facility=syslog.LOG_DAEMON):
        self.q = Queue()
        self.monitor_threadname = monitor_threadname
        self.senddata_threadname = senddata_threadname
        self.socket = socket
        self.debug = debug
        
        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog_facility)

    ########################################
    def put_in_queue(self, etat):
        try:
            self.q.put(etat)
        except:
            syslog.syslog(syslog.LOG_WARNING,  'monitor: problem while adding etat={} to the queue'.format(etat))

    ########################################
    def is_queue_empty(self):
        return self.q.empty()

    ########################################
    def monitor(self):
        pass

    ########################################
    def send_data(self):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data thread : start')
        
        sockdir = os.path.dirname(self.socket)
        if os.path.isdir(sockdir):
            try:
                os.remove(self.socket)
            except OSError:
                if os.path.exists(self.socket):
                    syslog.syslog(syslog.LOG_ERR, 'Can not remove {}'.format(self.socket))
                    os._exit(1)
        else:
            try:
                os.makedirs(sockdir, 0755)
            except:
                syslog.syslog(syslog.LOG_ERR, 'Can not create {}'.format(sockdir))
                os._exit(1)
                
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(self.socket)
            sock.listen(1)
        except:
            syslog.syslog(syslog.LOG_ERR, 'Can not initialize connection to {}'.format(self.socket))
            os._exit(1)
        
        while True:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data: waiting connection.')
            try:
                conn,  addr = sock.accept()
            except:
                syslog.syslog(syslog.LOG_WARNING,  'send_data: problem during sock.accept')
                break
            
            etat = '0'
            while True:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data: waiting for reception.')
                try:
                    data = conn.recv(7)
                except:
                    syslog.syslog(syslog.LOG_ERR, 'Can not read data from {}'.format(self.socket))
                    break
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'queue size : {}'.format(self.q.qsize()))
                while not self.q.empty():
                    try:
                        etat = self.q.get(True)
                    except:
                        syslog.syslog(syslog.LOG_WARNING,  'send_data: problem during queue.get')
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data: message received {}'.format(data))
                if data and data == 'status':
                    sdata = '{}:{}:status-end'.format(etat, time.time())
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data: sending {}'.format(sdata))
                    try:
                        conn.sendall(sdata)
                    except:
                        break
                else:
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'send_data: no more data')
                    break

            try:
                conn.close()
            except:
                syslog.syslog(syslog.LOG_WARNING,  'send_data: problem when closing connexion')

    ########################################
    def get_pid(self, binfile, warn_ppid_not_init=False):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG, 'get_pid: search {}'.format(binfile))
        try:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG, 'get_pid: doing process_iter')
            ret = []
            allprocess = psutil.process_iter()
        except psutil.NoSuchProcess:
            syslog.syslog(syslog.LOG_ERR, 'get_pid: NoSuchProcess error during psutil.process_iter')
            raise
        except psutil.AccessDenied:
            syslog.syslog(syslog.LOG_ERR, 'get_pid: AccessDenied error during psutil.process_iter')
            raise
        except psutil.TimeoutExpired:
            syslog.syslog(syslog.LOG_ERR, 'get_pid: TimeoutExpired error during psutil.process_iter')
            raise
        except:
            syslog.syslog(syslog.LOG_ERR, 'get_pid: unknown error during psutil.process_iter')
            raise
        else:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'get_pid: searching slapd process')
            for proc in allprocess:
                if psutil.pid_exists(proc.pid) and binfile in proc.cmdline() and proc.ppid() == 1:
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'get_pid: pid found with cdmdline={} pid={} ppid={}'.format(proc.cmdline(),proc.pid, proc.ppid()))
                    ret.append(proc.pid)
                elif warn_ppid_not_init and binfile in proc.cmdline():
                    syslog.syslog(syslog.LOG_WARN, 'get_pid: {} ppid ist not init,cdmdline={} pid={} ppid={}'.format(proc.cmdline(),proc.pid, proc.ppid()))
            if len(ret) == 0:
                msg = '{} not started'.format(binfile)
                syslog.syslog(syslog.LOG_INFO, msg)
                raise Mon4ocfError(1, msg)
            if len(ret) > 2:
                msg = 'More than a {} process'.format(binfile)
                syslog.syslog(syslog.LOG_ERR, msg)
                raise Mon4ocfError(1, msg)
            else:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'get_pid: {}'.format('pid={}'.format(ret[0]) if ret else 'pid not found'))

            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'get_pid: fin {}'.format(ret[0]))
            return ret[0]

    ########################################
    def is_process_just_start(self, binfile, start_delay):
        '''
        return True if start since less or equal than start_delay
        return False if start since more than start_delay
        raise if not start
        start_delai in seconds
        '''
        if self.debug: syslog.syslog(syslog.LOG_DEBUG, 'is_process_just_start')
        
        try:
            pid = self.get_pid(binfile)
        except:
            raise
        else:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG, 'is_process_just_start : verifying {}'.format(pid))
            try:
                if psutil.pid_exists(pid):
                    p = psutil.Process(pid)
            except:
                if self.debug: syslog.syslog(syslog.LOG_ERR, 'is_process_just_start error : pid {} does not exits anymore... should never happen'.format(pid))
                raise
            else:
                if time.time() <= p.create_time() + start_delay:
                    return True
                else:
                    return False
                
    
    ########################################
    def ldap_error_string(self, str,  err):
        if 'desc' in err.message:
            retstr = '{} : {}' .format(str,  err.message['desc'])
            if 'info' in err.message:
                retstr = '{} - {}'.format(retstr,  err.message['info'])
        else:
            retstr = '{} : {}\n' .format(str,  repr(err))
        return retstr

    ########################################
    def open_ldap_conn(self, uri, dn,  pw,  timelimit, timeout, nettimeout):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'open_ldap_conn on {}'.format(uri))
        l = None
        try:
            l = ldap.initialize(uri)
            l.protocol_version = ldap.VERSION3
            l.set_option(ldap.OPT_DEREF, ldap.DEREF_NEVER)
            l.set_option(ldap.OPT_TIMELIMIT, timelimit)
            l.set_option(ldap.OPT_TIMEOUT, timeout)
            l.set_option(ldap.OPT_NETWORK_TIMEOUT, nettimeout)
            if dn and pw:
                l.simple_bind_s(who=dn,  cred=pw)
            else:
                l.simple_bind_s()
        except ldap.LDAPError as e:
            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap connection {}'.format(uri), e))
            raise
        except:
            syslog.syslog(syslog.LOG_ERR, 'Error ldap connection {}: {}'.format(uri, sys.exc_info()))
            raise
        else:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'open_ldap_conn on {} OK'.format(uri))
            return l

    ########################################
    def stop_monitor(self, signum, thread):
        sys.exit(0)

    ########################################
    def run_thread(self):
        for signum in ['SIGINT','SIGQUIT','SIGTERM']:
            signal.signal(getattr(signal, signum), self.stop_monitor)
        
        t1 = Thread(target=self.monitor)
        t2 = Thread(target=self.send_data)
        t1.daemon  = True
        t2.daemon = True
        
        while True:
            if not t1.is_alive():
                syslog.syslog(syslog.LOG_INFO, 'Starting {} thread'.format(self.monitor_threadname))
                t1.start()
                #t1.join()
            if not t2.is_alive():
                syslog.syslog(syslog.LOG_INFO, 'Starting {} thread'.format(self.senddata_threadname))
                t2.start()
                #t2.join()
            time.sleep(5)

    ########################################
    def log_and_print(self, msg, sysloglvl=syslog.LOG_INFO):
        print(msg)
        syslog.syslog(sysloglvl, msg)
        return False

################################################################################
class MemcacheControl(object):
    ########################################
    def __init__(self, nodename, servers, nodes_list, key_expire, take_lock_timeout, lock_expire, election_expire, election_timeout, debug):
        
        self.nodename = nodename
        self.servers = servers
        self.nodes_list = nodes_list
        self.key_expire = key_expire
        self.take_lock_timeout = take_lock_timeout
        self.lock_expire = lock_expire
        self.lock_key = 'lock-key'
        self.election_key = 'election-key'
        self.election_expire = election_expire
        self.election_timeout = election_timeout
        self.debug = debug
        
        if self.debug: syslog.syslog(syslog.LOG_INFO, 'Opening a connexion on memcache for servers {}'.format(self.servers))
        self.mc = pylibmc.Client(self.servers) # TODO try/except
        self.mc.behaviors['ketama'] = True
        self.mc.behaviors['remove_failed'] = 1
        self.mc.behaviors['retry_timeout'] = 1
        self.mc.behaviors['dead_timeout'] = 60
        
    ########################################
    def set_nodes_list(self, nodes_list):
        if nodes_list:
            self.nodes_list = nodes_list
            
    ########################################
    def take_memcache_lock(self, key=None, timeout=None, expire=None, strtype='lock'):
        if not key: key = self.lock_key
        if not timeout: timeout = self.take_lock_timeout
        if not expire: expire = self.lock_expire
        
        timeout_time = time.time() + timeout
        while time.time() < timeout_time:
            # verify if a lock exist
            try:
                val = self.mc.get(key)
            except pylibmc.Error as e:
                syslog.syslog(syslog.LOG_ERR, "take_memcache_lock get error: {}".format(e))
            except:
                syslog.syslog(syslog.LOG_ERR, "take_memcache_lock get error")
            else:
                if not val or val == self.nodename:
                    # lock does not exist (or exist for me), creating it
                    if val and val == self.nodename:
                        syslog.syslog(syslog.LOG_WARNING, '{} still exist for me (WTF ?), recreating it'.format(strtype))
                    else:
                        if self.debug: syslog.syslog(syslog.LOG_INFO, 'creating {} in memcache'.format(strtype))
                    
                    try:
                        self.mc.set(key, self.nodename, expire)
                        # verifying that i got the lock
                        val = self.mc.get(key)
                    except pylibmc.Error as e:
                        syslog.syslog(syslog.LOG_ERR, "take_memcache_lock set/get error: {}".format(e))
                    except:
                        syslog.syslog(syslog.LOG_ERR, "take_memcache_lock set/get error")
                    else:
                        if not val:
                            syslog.syslog(syslog.LOG_WARNING, 'The {} should exist but not, retrying...'.format(strtype))
                        else:
                            if val == self.nodename:
                                if self.debug: syslog.syslog(syslog.LOG_INFO, 'I got the memcache {}'.format(strtype))
                                return True
                            else:
                                if self.debug: syslog.syslog(syslog.LOG_INFO, 'Does not have the {}, {} was faster than me : waiting...'.format(strtype,val))
                                time.sleep(random.random() * 0.25)
                else:
                    if self.debug: syslog.syslog(syslog.LOG_INFO, '{} is not free : waiting...'.format(strtype))
                    time.sleep(random.random() * 0.25)
        else:
            return False

    ########################################
    def release_memcache_lock(self, key=None, strtype='lock'):
        if not key: key = self.lock_key
        try:
            # verify if a lock exist
            val = self.mc.get(key)
        except pylibmc.Error as e:
            syslog.syslog(syslog.LOG_ERR, "release_memcache_lock get error: {}".format(e))
        except:
            syslog.syslog(syslog.LOG_ERR, "release_memcache_lock get error")
        else:
            if not val or val != self.nodename:
                syslog.syslog(syslog.LOG_WARNING, '{} is not mine (WTF ?),I did not delete it.'.format(strtype))
            else:
                if self.debug: syslog.syslog(syslog.LOG_INFO, 'deleting {}'.format(strtype))
                try:
                    self.mc.delete(key)
                except pylibmc.Error as e:
                    syslog.syslog(syslog.LOG_ERR, "release_memcache_lock delete error: {}".format(e))
                except:
                    syslog.syslog(syslog.LOG_ERR, "release_memcache_lock delete error")

    ########################################
    def delete_key(self, key):
        if self.take_memcache_lock():
            try:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'deleting key {}'.format(key))
                self.mc.delete(key)
            except pylibmc.Error as e:
                syslog.syslog(syslog.LOG_ERR, "delete_key error: {}".format(e))
                raise
            except:
                syslog.syslog(syslog.LOG_ERR, "delete_key error")
                raise
            finally:
                self.release_memcache_lock()

    ########################################
    def am_i_elected(self):
        ret = False
        if self.take_memcache_lock():
            if self.take_memcache_lock(key=self.election_key, timeout=self.election_timeout, expire=self.election_expire, strtype=self.election_key):
                ret = True
            self.release_memcache_lock()
        return ret
    
    ########################################
    def release_election_node_send_ko(self):
       pass