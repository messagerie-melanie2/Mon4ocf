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

import sys,  argparse, syslog, os, time, string, random, hashlib, ldap, ldap.modlist, configparser, pylibmc, subprocess, re
from mon4ocf import Mon4ocfError, Mon4ocf, MemcacheControl


################################################################################
class MemcacheControlReplic(MemcacheControl):
    ########################################
    def __init__(self, nodename, servers, key_expire, take_lock_timeout, lock_expire, max_node_replic_broken, nodes_list, state_no_send, election_expire, election_timeout, debug, \
        replic_state=['REPLIC_OK', 'REPLIC_NOT_CHECK', 'REPLIC_KO_NOT_SEND', 'REPLIC_KO_SEND', 'REPLIC_UNKOWN', 'REPIC_WAITING_ENTRY', 'NO_SLAPD']):
  
        self.max_node_replic_broken = max_node_replic_broken
        self.replic_state = replic_state
        self.state = dict(zip(self.replic_state,range(len(self.replic_state))))
        self.state_no_send = self.make_state_no_send(state_no_send)
        
        super(self.__class__, self).__init__(nodename, servers, nodes_list, key_expire, take_lock_timeout, lock_expire, election_expire, election_timeout, debug)

            
    ########################################
    def make_state_no_send(self, state_no_send):
        csk = state_no_send.rstrip(',').split(',')
        return csk
        #if all(x in self.state_no_send for x in self.replic_state):
            #return csk
        #else:
            #if self.debug: syslog.syslog(syslog.LOG_ERR, 'Config : some replication state are not valid {}'.format(state_no_send))
            #return XXXXXXX? #TODO
    
    ########################################
    def set_repic_state(self, value):
        
        if self.take_memcache_lock():
            try:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'writing memached replic_state, nodename={}, state={}'.format(self.nodename, self.replic_state[value]))
                self.mc.set(self.nodename, self.replic_state[value], self.key_expire)
            except pylibmc.Error as e:
                syslog.syslog(syslog.LOG_ERR, "set_repic_state set error: {}".format(e))
            except:
                syslog.syslog(syslog.LOG_ERR, "set_repic_state set error")
            else:
                self.release_memcache_lock()
                return True
        else:
            syslog.syslog(syslog.LOG_ERR, '{}:{} can not be write'.format(self.nodename,repr(value)))
        
        return False

    ########################################
    def is_replic_ko_can_be_send(self):
        ret = False
        if self.take_memcache_lock():
            nb_replic_broken = 0
            for node in self.nodes_list:
                if node != self.nodename:
                    node_state = self.mc.get(node)
                    if not node_state or node_state in self.state_no_send:
                        nb_replic_broken += 1

            if nb_replic_broken < self.max_node_replic_broken:
                # nb_replic_broken < self.max_node_replic_broken
                # I can say that replication is not working
                if self.debug: syslog.syslog(syslog.LOG_INFO, 'replic is broken on {} other nodes, set memcache to replic_ko_send'.format(nb_replic_broken))
                try:
                    self.mc.set(self.nodename, self.replic_state[self.state['REPLIC_KO_SEND']], self.key_expire)
                except pylibmc.Error as e:
                    syslog.syslog(syslog.LOG_ERR, "is_replic_ko_can_be_send set error: {}".format(e))
                except:
                    syslog.syslog(syslog.LOG_ERR, "is_replic_ko_can_be_send set error")
                else:
                    ret = True # To use release_memcache_lock
            else:
                syslog.syslog(syslog.LOG_WARNING, 'replic is broken on {} other nodes, can not set memcache to replic_ko_send'.format(nb_replic_broken))
                
            self.release_memcache_lock()
        return ret
    

################################################################################
class MonReplicDefault(object):
    '''
    Defaults values
    '''
    ########################################
    def __init__(self):
        self.valid_check = ['csn', 'write', 'both']
        self.curi = 'ldap://localhost'
        self.start_delay = 900
        self.binfile = '/usr/sbin/slapd'
        self.timeout = 300
        self.interval = 300
        self.search_interval = 1
        self.time_error = 1
        self.socket = '/var/run/mon-charge-ldap/socket/mon'
        self.ldaptimelimit = 10
        self.ldaptimeout = 10
        self.sleep = 5
        self.network_timeout = 5
        self.debug = False
        self.memcache = False
        self.mc_key_expire = 20
        self.max_node_replic_broken = 1
        self.mc_take_lock_timeout = 5
        self.mc_lock_expire = 20
        self.state_no_send = 'REPLIC_NOT_CHECK,REPLIC_KO_SEND,REPLIC_UNKOWN,REPIC_WAITING_ENTRY,NO_SLAPD'
        self.mc_election_expire = 10
        self.mc_election_timeout = 10

################################################################################
class MonReplicSlapd(Mon4ocf):
    ########################################
    def __init__(self, syslog_facility=syslog.LOG_DAEMON):
        self.nodename = os.uname()[1]
        self.defval = MonReplicDefault()
        args, conffile = self.parse_all_args()
        
        syslog.openlog(logoption=syslog.LOG_PID, facility=syslog_facility)
        is_config_file_ok = True
        if args.check == 'file':
            try:
                log_config = conffile.getboolean('DEFAULT', 'logconfig', fallback=False)
                log_passwd = conffile.getboolean('DEFAULT', 'logpasswd', fallback=False)
                if log_passwd:
                    self.log_and_print('Warning : logging password is a security hole', sysloglvl=syslog.LOG_WARNING)
            except configparser.Error as e:
                is_config_file_ok = self.log_and_print('error in configuration file : {}'.format(e), sysloglvl=syslog.LOG_ERR)
            except:
                is_config_file_ok = self.log_and_print('error in configuration file', sysloglvl=syslog.LOG_ERR)
            
            try:
                self.check = conffile.get('DEFAULT', 'type')
            except:
                is_config_file_ok = self.log_and_print('type must be define in configuration file in DEFAULT section', sysloglvl=syslog.LOG_ERR)
            else:
                if self.check not in self.defval.valid_check:
                    is_config_file_ok = self.log_and_print('type not in {} in configuration file in DEFAULT section'.format(self.defval.valid_check), sysloglvl=syslog.LOG_ERR)
                else:
                    if log_config: self.log_and_print('type : {}'.format(self.check))

            try:
                self.suffix = conffile.get('DEFAULT', 'suffix')
            except:
                if self.check in ['csn', 'both']:
                    is_config_file_ok = self.log_and_print('suffix must be define in configuration file in DEFAULT section', sysloglvl=syslog.LOG_ERR)
            else:
                if log_config: self.log_and_print('suffix : {}'.format(self.suffix))

            try:
                self.base = conffile.get('DEFAULT', 'base')
            except:
                if self.check in ['write', 'both']:
                    is_config_file_ok = self.log_and_print('base must be define in configuration file in DEFAULT section', sysloglvl=syslog.LOG_ERR)
            else:
                if log_config: self.log_and_print('base : {}'.format(self.base))

            try:
                self.puri = conffile.get('DEFAULT', 'puri')
            except:
                is_config_file_ok = self.log_and_print('puri (provider uri) must be define in configuration file in DEFAULT section', sysloglvl=syslog.LOG_ERR)
            else:
                if log_config: self.log_and_print('puri : {}'.format(self.puri))

            try:
                self.curi = conffile.get('DEFAULT', 'curi', fallback=self.defval.curi)
                if log_config: self.log_and_print('curi : {}'.format(self.curi))
                self.start_delay = conffile.getint('DEFAULT', 'start_delay', fallback=self.defval.start_delay)
                if log_config: self.log_and_print('start_delay : {}'.format(self.start_delay))
                self.binfile = conffile.get('DEFAULT', 'binfile', fallback=self.defval.binfile)
                if log_config: self.log_and_print('binfile : {}'.format(self.binfile))
                self.timeout = conffile.getint('DEFAULT', 'timeout', fallback=self.defval.timeout)
                if log_config: self.log_and_print('timeout : {}'.format(self.timeout))
                self.interval = conffile.getint('DEFAULT', 'interval', fallback=self.defval.interval)
                if log_config: self.log_and_print('interval : {}'.format(self.interval))
                self.search_interval = conffile.getint('DEFAULT', 'search_interval', fallback=self.defval.search_interval)
                if log_config: self.log_and_print('search_interval : {}'.format(self.search_interval))
                self.time_error = conffile.getint('DEFAULT', 'time_error', fallback=self.defval.time_error)
                if log_config: self.log_and_print('time_error : {}'.format(self.time_error))
                socket = conffile.get('DEFAULT', 'socket', fallback=self.defval.socket)
                if log_config: self.log_and_print('socket : {}'.format(socket))
                self.ldaptimelimit = conffile.getint('DEFAULT', 'ldaptimelimit', fallback=self.defval.ldaptimelimit)
                if log_config: self.log_and_print('ldaptimelimit : {}'.format(self.ldaptimelimit))
                self.ldaptimeout = conffile.getint('DEFAULT', 'ldaptimeout', fallback=self.defval.ldaptimeout)
                if log_config: self.log_and_print('ldaptimeout : {}'.format(self.ldaptimeout))
                self.sleep = conffile.getint('DEFAULT', 'sleep', fallback=self.defval.sleep)
                if log_config: self.log_and_print('sleep : {}'.format(self.sleep))
                self.network_timeout = conffile.getint('DEFAULT', 'network_timeout', fallback=self.defval.network_timeout)
                if log_config: self.log_and_print('network_timeout : {}'.format(self.network_timeout))
                debug = conffile.getboolean('DEFAULT', 'debug', fallback=self.defval.debug)
                if log_config: self.log_and_print('debug : {}'.format(debug))
                
                self.dnwriter = conffile.get('WRITER', 'dnwriter', fallback=None)
                if log_config: self.log_and_print('dnwriter : {}'.format(self.dnwriter))
                self.passwdwrite  = conffile.get('WRITER', 'passwdwrite', fallback=None)
                if log_config and log_passwd: self.log_and_print('passwdwrite : {}'.format(self.passwdwrite))

                self.dnreader = conffile.get('READER', 'dnreader', fallback=None)
                if log_config: self.log_and_print('dnreader : {}'.format(self.dnreader))
                self.passwordread = conffile.get('READER', 'passwordread', fallback=None)
                if log_config and log_passwd: self.log_and_print('passwordread : {}'.format(self.passwordread))
            
                self.memcache = conffile.getboolean('MEMCACHE', 'memcache', fallback=self.defval.memcache)
                if log_config: self.log_and_print('memcache : {}'.format(self.memcache))
                self.mc_servers = self.create_memcache_servers_list( conffile.get('MEMCACHE', 'mc_servers', fallback=None) )
                if self.memcache and not self.mc_servers:
                    is_config_file_ok = self.log_and_print('if memcache true, mc_servers must be set', sysloglvl=syslog.LOG_ERR)
                if log_config: self.log_and_print('mc_servers : {}'.format(self.mc_servers))
                self.mc_key_expire = conffile.getint('MEMCACHE', 'mc_key_expire', fallback=self.defval.mc_key_expire)
                if log_config: self.log_and_print('mc_key_expire : {}'.format(self.mc_key_expire))
                self.max_node_replic_broken = conffile.getint('MEMCACHE', 'max_node_replic_broken', fallback=self.defval.max_node_replic_broken)
                if log_config: self.log_and_print('max_node_replic_broken : {}'.format(self.max_node_replic_broken))
                self.nodes_list = conffile.get('MEMCACHE', 'nodes_list', fallback=None)
                if self.memcache and not self.nodes_list:
                    is_config_file_ok = self.log_and_print('if memcache true, nodes_list must be set', sysloglvl=syslog.LOG_ERR)
                if log_config: self.log_and_print('nodes_list : {}'.format(self.nodes_list))
                self.mc_take_lock_timeout = conffile.getint('MEMCACHE', 'mc_take_lock_timeout', fallback=self.defval.mc_take_lock_timeout)
                if log_config: self.log_and_print('mc_take_lock_timeout : {}'.format(self.mc_take_lock_timeout))
                self.mc_lock_expire = conffile.getint('MEMCACHE', 'mc_lock_expire', fallback=self.defval.mc_lock_expire)
                if log_config: self.log_and_print('mc_lock_expire : {}'.format(self.mc_lock_expire))
                self.state_no_send = conffile.get('MEMCACHE', 'state_no_send', fallback=self.defval.state_no_send)
                if log_config: self.log_and_print('state_no_send : {}'.format(self.state_no_send))
                self.mc_election_expire = conffile.getint('MEMCACHE', 'mc_election_expire', fallback=self.defval.mc_election_expire)
                if log_config: self.log_and_print('mc_election_expire : {}'.format(self.mc_election_expire))
                self.mc_election_timeout = conffile.getint('MEMCACHE', 'mc_election_timeout', fallback=self.defval.mc_election_timeout)
                if log_config: self.log_and_print('mc_election_timeout : {}'.format(self.mc_election_timeout))
            except configparser.Error as e:
                is_config_file_ok = self.log_and_print('error in configuration file : {}'.format(e))
            except:
                is_config_file_ok = self.log_and_print('error in configuration file')

            if not is_config_file_ok:
                self.log_and_print('Error in configuration file : aborting !')
                sys.exit(1)
        else:
            self.check = args.check
            self.suffix = args.suffix
            self.base = args.base
            self.puri = args.puri
            self.curi = args.curi
            self.dnwriter = args.dnwriter
            self.passwdwrite = args.passwdwrite
            self.dnreader = args.dnreader
            self.passwordread = args.passwordread
            self.start_delay = args.start_delay
            self.binfile = args.binfile
            self.timeout = args.timeout
            self.interval = args.interval
            self.search_interval = args.search_interval
            self.time_error = args.time_error
            socket = args.socket
            self.ldaptimelimit = args.ldaptimelimit
            self.ldaptimeout = args.ldaptimeout
            self.sleep = args.sleep
            self.network_timeout = args.network_timeout
            debug = True if args.debug else False
            self.memcache = True if args.memcache else False
            self.mc_servers = self.create_memcache_servers_list( args.mc_servers ) #TODO CONTROL
            self.mc_key_expire = args.mc_key_expire
            self.max_node_replic_broken = args.max_node_replic_broken #TODO CONTROL
            self.nodes_list = args.nodes_list
            self.mc_take_lock_timeout = args.mc_take_lock_timeout
            self.mc_lock_expire = args.mc_lock_expire
            self.state_no_send = args.state_no_send
            self.mc_election_expire = args.mc_election_expire
            self.mc_election_timeout = args.mc_election_timeout
        
        super(self.__class__, self).__init__("monitor", "send_data", socket, debug) #TODO
        
        if self.memcache:
            self.mcr = MemcacheControlReplic(self.nodename, self.mc_servers, self.mc_key_expire, self.mc_take_lock_timeout, self.mc_lock_expire, self.max_node_replic_broken, self.make_nodes_list(), \
                self.state_no_send, self.mc_election_expire, self.mc_election_timeout, self.debug)

    ########################################
    def parse_common_args(self, cparser):
        # common arguments are see in each subparsers
        cparser.add_argument('-u', '--puri','--uri', help='uri of syncrepl\'s provider', required=True)
        cparser.add_argument('--curi', help='uri of syncrepl\'s consumer', default=self.defval.curi)
        writer = cparser.add_argument_group('writer')
        writer.add_argument('-w', '--dnwriter',  help='dn used to write entries on the syncrepl\'s provider. none=anaonymous', metavar='DN')
        writer.add_argument('-p', '--passwdwrite', help='password for dn used to write entries.')
        reader = cparser.add_argument_group('reader')
        reader.add_argument('-r',  '--dnreader',  help='dn used to read entries on the consumer. none=anaonymous',  metavar='DN')
        reader.add_argument('-P', '--passwordread',  help='password for dn used to read entries.')
        nocheck = cparser.add_argument_group('nocheck')
        nocheck.add_argument('--start_delay', help='delay in seconds before beginnig monitoring', metavar='DELAY', default=self.defval.start_delay, type=int)
        nocheck.add_argument('--binfile',  help='openldap binary file',  metavar='BINFILE',  default='/usr/sbin/slapd')
        cparser.add_argument('-t',  '--timeout',  help='timeout between read and write and replication. defaut=300',  metavar='TIMEOUT',  default=self.defval.timeout, type=int)
        cparser.add_argument('-i',  '--interval', help='inteval in secondes between each monitoring. defaut=300',  metavar='INTERVAL',  default=self.defval.interval, type=int)
        cparser.add_argument('--search_interval', help='inteval in secondes between each search. defaut=1',  metavar='INTERVAL',  default=self.defval.search_interval, type=int)
        cparser.add_argument('--time_error', help='sleep time in secondes when an error occure. defaut=1',  metavar='TIME',  default=self.defval.time_error, type=int)
        cparser.add_argument('-s',  '--socket',  help='socket for writing result. defaut=/var/run/mon-charge-ldap/socket/mon',  metavar='SOCKET',  default=self.defval.socket)
        cparser.add_argument('-l',  '--ldaptimelimit',  help='Specify a time limit (in seconds) to use when performing searches.',  default=self.defval.ldaptimelimit, type=int)
        cparser.add_argument('-L',  '--ldaptimeout',  help='Specify  a  timeout  (in  seconds) after which calls to synchronous LDAP APIs will abort if no response is received.',  default=self.defval.ldaptimeout,  type=int)
        cparser.add_argument('--sleep', help='Sleep in secondes before checking for replication', metavar='TIME',  default=self.defval.sleep, type=int)
        cparser.add_argument('-n', '--network_timeout', help='ldap network timeout', metavar='TIMEOUT', default=self.defval.network_timeout,  type=int)
        cparser.add_argument('-d','--debug',  help='mode debug on',  action='store_true')
        memcache = cparser.add_argument_group('memcache')
        memcache.add_argument('--memcache',  help='mode memcache on',  action='store_true')
        memcache.add_argument('--mc_servers', help='memcached servers <server:port,server:port,server:port,...>')
        memcache.add_argument('--mc_key_expire', help='time in seconds of expiration of a key', default=self.defval.mc_key_expire, type=int)
        memcache.add_argument('--max_node_replic-broken', help='maximum number of node with replication broken', default=self.defval.max_node_replic_broken, type=int)
        memcache.add_argument('--nodes_list', help='node list must cooperate to not declare a replication problem simultaneously. With "find_crm,path to crm command" the program search node list with crm command')
        memcache.add_argument('--mc_take_lock_timeout', help='timeout while trying to take a lock on memcache', default=self.defval.mc_take_lock_timeout, type=int)
        memcache.add_argument('--mc_lock_expire', help='time after while lock expire in case of problem', default=self.defval.mc_lock_expire, type=int)
        memcache.add_argument('--state_no_send', help='Liste of state for witch the script not send that replication is broken. State are REPLIC_OK,REPLIC_NOT_CHECK,REPLIC_KO_NOT_SEND,REPLIC_KO_SEND,REPLIC_UNKOWN,REPIC_WAITING_ENTRY,NO_SLAP. Default: REPLIC_NOT_CHECK,REPLIC_KO_SEND,REPLIC_UNKOWN,REPIC_WAITING_ENTRY,NO_SLAPD', default=self.defval.state_no_send)
        memcache.add_argument('--mc_election_expire', help='time after while lock expire in case of problem', default=self.defval.mc_election_expire, type=int)
        memcache.add_argument('--mc_election_timeout', help='time after while lock expire in case of problem', default=self.defval.mc_election_timeout, type=int)

    ########################################
    def parse_all_args(self):
        parser = argparse.ArgumentParser(description="monitor openldap directory replication")

        subparsers = parser.add_subparsers(dest='check')
        parser_csn = subparsers.add_parser('csn', help='check replication with contextCSN')
        parser_csn.add_argument('-S', '--suffix', help='suffix of the DSN',  metavar='SUFFIX', required=True)
        self.parse_common_args(parser_csn)
        
        parser_write = subparsers.add_parser('write', help='check replication by creating an entry in the directory ')
        parser_write.add_argument('-b', '--base', help='base used to create entries', metavar='BASE', required=True)
        self.parse_common_args(parser_write)
        
        parser_both = subparsers.add_parser('both', help='check replication by contextCSN and creating an entry in the directory')
        parser_both.add_argument('-S', '--suffix', help='suffix of the DSN',  metavar='SUFFIX', required=True)
        parser_both.add_argument('-b', '--base', help='base used to create entries', metavar='BASE', required=True)
        self.parse_common_args(parser_both)
        
        parser_file = subparsers.add_parser('file', help='configuration is read from configuration file')
        parser_file.add_argument('conffile', help='path to configuration file')
        
        args = parser.parse_args()
        if args.check == 'file':
            configfile = configparser.ConfigParser()
            configfile.read(args.conffile)
        else:
            configfile = None

        return (args, configfile)

    
    ########################################
    def create_memcache_servers_list(self, mc_servers):
        if mc_servers:
            return mc_servers.rstrip(',').split(',')
        else:
            return None

    ########################################
    def random_passwd(self, size=50, chars=string.printable):
        password = ''.join(random.choice(chars) for _ in range(size))
        salt = os.urandom(16)
        sha = hashlib.sha1(password)
        sha.update(salt)
        digest_salt_b64 = '{}{}'.format(sha.digest(), salt).encode('base64').strip()
        tagged_digest_salt = '{{SSHA}}{}'.format(digest_salt_b64)
        return tagged_digest_salt

    ########################################
    def create_mon_entry(self, l, rdn, dn, nodename):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'create_mon_entry')
        attrs = {}
        attrs['objectClass'] = ['top', 'organizationalRole', 'simpleSecurityObject']
        attrs['cn'] = [rdn]
        attrs['description'] = ['test sycrepl {}'.format(nodename)]
        attrs['userPassword'] = [self.random_passwd()]
        
        try:
            l.add_s(dn, ldap.modlist.addModlist(attrs))
        except ldap.LDAPError as e:
            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error during ldap add:', e))
            raise
        except:
            syslog.syslog(syslog.LOG_ERR, 'Error during ldap add: {}'.format(sys.exc_info()))
            raise

    ########################################
    def cleaning_before_start(self, uri, cred, pwd, base, timelimit, timeout, nettimeout, nodename):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'cleaning_before_start')
        try:
            l = self.open_ldap_conn(uri, cred, pwd, timelimit, timeout, nettimeout)
        except ldap.LDAPError as e:
            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap connection {}: '.format(uri), e))
        except:
            syslog.syslog(syslog.LOG_ERR, 'Error ldap connection {}: {}'.format(uri, repr(sys.exc_info())))

        try:
            res = l.search_s(base, ldap.SCOPE_SUBTREE, '(cn={}*)'.format(nodename))
            for dn,entry in res:
                l.delete(dn)
            l.unbind()
        except ldap.LDAPError as e:
            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap', e))
        except:
            syslog.syslog(syslog.LOG_ERR, 'Error ldap {}'.format(sys.exc_info()))
        else:
            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'cleaning_before_start ok')

    ########################################
    def get_last_csn(self, l, suffix):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'get_last_csn')
        try:
            csn = 0
            res = l.search_s(suffix, ldap.SCOPE_BASE, attrlist=['contextCSN'])
            for dn, entry in res:
                if 'contextCSN' in entry:
                    max = 0
                    for i in entry['contextCSN']:
                        ts = i.split('#')[0][:-1]
                        if ts > max:
                            max = ts
                            csn = i
                    break
                #else:
                    #syslog.syslog(syslog.LOG_ERR, 'contextCSN not found')
                    #raise
            else:
                msg = 'contextCSN not found'
                syslog.syslog(syslog.LOG_ERR, msg)
                raise Mon4ocfError(1, msg)
        except ldap.LDAPError as e:
            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('contextCSN search error:', e))
            raise
        except:
            syslog.syslog(syslog.LOG_ERR, 'contextCSN search error')
            raise
        else:
            return csn

    ########################################
    def is_csn_replic(self, pcsn, ccsn):
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'is_csn_replic pcsn={}, ccsn={}'.format(pcsn,ccsn))
        #if pcsn == ccsn:
            #return True
        #else:
            #pts = pcsn.split('#')[0][:-1]
            #cts = ccsn.split('#')[0][:-1]
            #if cts <= pts:
                #return False
            #else:
                #return True
        if pcsn != ccsn:
            pts = pcsn.split('#')[0][:-1]
            cts = ccsn.split('#')[0][:-1]
            if cts <= pts:
                raise Mon4ocfError(1, 'consumer contextCSN is inferior or equal to provider contextCSN')

    ########################################
    def make_nodes_list(self):
        if self.nodes_list:
            nl = self.nodes_list.rstrip(',').split(',')
            if nl[0] == 'find_crm' and len(nl) == 2:
                if os.path.isfile(nl[1]):
                    try:
                        out = subprocess.check_output([nl[1],  'node', 'show'])
                    except subprocess.CalledProcessError as cpe:
                        self.ocf_log_err('{} error:{}, command line = {},'.format(nl[1],cpe.returncode,cpe.cmd))
                        raise
                    except OSError as ose:
                        self.ocf_log_err('{} error: {}'.format(nl[1],ose.strerror))
                        raise
                    except:
                        self.ocf_log_err('{} error: unknown error'.format(nl[1]))
                        raise
                    
                    calc_nodes=[]
                    for n in out.splitlines():
                        g=re.match(r'^(\w.*?):.*?$', n)
                        if g:
                            calc_nodes.append(g.group(1))
                            
                    return calc_nodes
                else:
                    raise Mon4ocfError(1, '{} does not existe or is not a file !'.format(nl[1]))
            else:
                return nl
        else:
            raise Mon4ocfError(1, 'self.nodes_list is empty !')
        

    ########################################
    def monitor(self):
        '''
        etat=0 => OK
        etat=1 => KO
        '''
        if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : start')

        if self.check in ['write', 'both']:
            self.cleaning_before_start(self.puri, self.dnwriter, self.passwdwrite, self.base, self.ldaptimelimit, self.ldaptimeout, self.network_timeout, self.nodename)
        
        while True:
            try:
                ipjs = self.is_process_just_start(self.binfile, self.start_delay)
            except:
                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : {} not started'.format(self.binfile))
                if self.memcache: self.mcr.set_repic_state(self.mcr.state['NO_SLAPD'])
            else:
                if ipjs:
                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : {} just start. Waiting for beginnig monitoring'.format(self.binfile))
                    if self.memcache: self.mcr.set_repic_state(self.mcr.state['REPLIC_NOT_CHECK'])
                else:
                    if self.memcache: self.mcr.set_nodes_list(self.make_nodes_list())
                    
                    p = c = None
                    try:
                        p = self.open_ldap_conn(self.puri, self.dnwriter, self.passwdwrite, self.ldaptimelimit, self.ldaptimeout, self.network_timeout)
                        c = self.open_ldap_conn(self.curi, self.dnreader,  self.passwordread,  self.ldaptimelimit, self.ldaptimeout, self.network_timeout)
                    except:
                        syslog.syslog(syslog.LOG_ERR, 'monitor thread : Abording this test due to ldap connexion problem... {}'.format(sys.exc_info()))
                        if self.memcache: self.mcr.set_repic_state(self.mcr.state['REPLIC_UNKOWN'])
                        time.sleep(self.time_error)
                    else:
                        try:
                            ctime = time.time()
                            if self.check in ['csn', 'both']:
                                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : reading contextCSN on {}'.format(self.puri))
                                pcsn = self.get_last_csn(p, self.suffix)
                            if self.check in ['write', 'both']:
                                rdn='{}.{}'.format(self.nodename,ctime)
                                dn='cn={},{}'.format(rdn, self.base)
                                if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : creating entry on {}'.format(self.puri))
                                self.create_mon_entry(p, rdn, dn, self.nodename)
                        except:
                            syslog.syslog(syslog.LOG_ERR, 'monitor thread : abording this test...')
                            if self.memcache: self.mcr.set_repic_state(self.mcr.state['REPLIC_UNKOWN'])
                            time.sleep(self.time_error)
                        else:
                            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : waiting {} secondes before checking'.format(self.sleep))
                            time.sleep(self.sleep)
                            if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : check value')
                            # Verifying entry
                            maxtime = ctime+self.timeout
                            while time.time() < maxtime:
                                try:
                                    if self.check in ['csn', 'both']:
                                        ccsn = self.get_last_csn(c, self.suffix)
                                        self.is_csn_replic(pcsn, ccsn)
                                    if self.check in ['write', 'both']:
                                        c.search_s(dn, ldap.SCOPE_BASE)
                                # TODO Traiter le cas des déconnexions ldap à coup de except
                                except ldap.SERVER_DOWN:
                                    syslog.syslog(syslog.LOG_ERR,  'monitor thread : ldap server is down, abording this test...')
                                    if self.memcache: self.mcr.set_repic_state(self.mcr.state['NO_SLAPD'])
                                    time.sleep(self.time_error)
                                    break
                                except:
                                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : entry not replicated on consumer for now. waiting...')
                                    if self.memcache: self.mcr.set_repic_state(self.mcr.state['REPIC_WAITING_ENTRY'])
                                #except ldap.LDAPError as e:
                                    #syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap connection', e))
                                #except:
                                    #syslog.syslog(syslog.LOG_ERR, 'Error ldap connection {}: {}'.format(i, repr(sys.exc_info())))
                                else:
                                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : entry found')
                                    if self.memcache: self.mcr.set_repic_state(self.mcr.state['REPLIC_OK'])
                                    self.put_in_queue('0')
                                    break
                                time.sleep(self.search_interval)
                            else:
                                syslog.syslog(syslog.LOG_ERR,  'monitor thread : entry not replicated on consumer.')
                                if self.memcache:
                                    self.mcr.set_repic_state(self.mcr.state['REPLIC_KO_NOT_SEND'])
                                    if self.mcr.is_replic_ko_can_be_send():
                                        self.put_in_queue('1')
                                    else:
                                        syslog.syslog(syslog.LOG_ERR,  'monitor thread : memcache exclusion, can not send to slapd replication problem, abording this test...')
                                else:
                                    self.put_in_queue('1')
                            
                            if self.check in ['write', 'both']:
                                # delete entry
                                try:
                                    p.delete_s(dn)
                                except ldap.LDAPError as e:
                                    syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap delete', e))
                                except:
                                    syslog.syslog(syslog.LOG_ERR, 'Error ldap delete: {}'.format(sys.exc_info()))
                                else:
                                    if self.debug: syslog.syslog(syslog.LOG_DEBUG,  'monitor thread : entry deleted')
                    finally:
                        try:
                            if p: p.unbind()
                            if c: c.unbind()
                        except ldap.LDAPError as e:
                            syslog.syslog(syslog.LOG_ERR, self.ldap_error_string('Error ldap unbind', e))
                        except:
                            syslog.syslog(syslog.LOG_ERR, 'Error ldap unbind: {}'.format(sys.exc_info()))
            finally:
                # sleep
                time.sleep(self.interval)
                
    ########################################
    def stop_monitor(self, signum, thread):
        try:
            self.mcr.delete_key(self.nodename)
        except:
            pass
        sys.exit(0)

################################################################################
if __name__ == '__main__':
    if os.getuid() != 0:
        print ('you must be root')
        sys.exit(1)
        
    mrs = MonReplicSlapd()
    mrs.run_thread()
    