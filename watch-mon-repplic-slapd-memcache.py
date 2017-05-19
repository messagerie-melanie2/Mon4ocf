#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# http://memcached.org/
# http://sendapatch.se/projects/pylibmc/

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

import sys, time, pylibmc, argparse, sys

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="See memcached key used by mon-replic-slapd")
    parser.add_argument('-s', '--servers', help='Servers memcached : <server,server,server,...>', required=True)
    parser.add_argument('-n', '--nodes', help='keys for nodes : <node,node,node,...>')
    parser.add_argument('-i', '--interval', help='in secondes. Could be a float', default='0.1', type=float)
    args = parser.parse_args()

    srvs = args.servers.rstrip(',').split(',')
    
    if args.nodes :
        nodes = args.nodes.rstrip(',').split(',')
    else:
        nodes = []
        for i in srvs: nodes.append(i.split('.',1)[0])
    
    mc = pylibmc.Client(srvs)
    mc.behaviors['ketama'] = True
    mc.behaviors['remove_failed'] = 1
    mc.behaviors['retry_timeout'] = 1
    mc.behaviors['dead_timeout'] = 60

    while True:
        try:
            str='lock={}'.format(mc.get('lock-key'))
            for n in nodes:
                str='{}\t{}'.format(str,mc.get(n))
            str='{}\n'.format(str)
            sys.stdout.write(str)
        except pylibmc.Error as e:
            sys.stderr.write('memcache error: {}'.format(e))
        except:
            sys.stderr.write('unknown error: {}'.format(sys.exc_info()))
        finally:
            time.sleep(args.interval)
