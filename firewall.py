'''
Coursera:
- Software Defined Networking (SDN) course
-- Module 4 Programming Assignment

Professor: Nick Feamster
Teaching Assistant: Muhammad Shahbaz
'''

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
from collections import namedtuple
import os
''' Add your imports here ... '''
import csv


log = core.getLogger()
policyFile = "%s/pox/pox/misc/firewall-policies.csv" % os.environ[ 'HOME' ]  

''' Add your global variables here ... '''



class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.debug("Enabling Firewall Module")
        self.blacklist = []
        with open(policyFile, 'rb') as f:
            reader = csv.DictReader(f)
            for entry in reader:
                self.blacklist.append((
                EthAddr(entry['mac_0']), EthAddr(entry['mac_1'])))

    def _handle_ConnectionUp (self, event):    
        ''' Add your logic here ... '''

        for (src, dst) in self.blacklist:
            match = of.ofp_match()
            match.dl_src = src
            match.dl_dst = dst

            msg = of.ofp_flow_mod()
            msg.match = match

            event.connection.send(msg)

            match.dl_src = dst
            match.dl_dst = src

            msg.match = match

            event.connection.send(msg)

        log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch ():
    '''
    Starting the Firewall module
    '''
    core.registerNew(Firewall)
