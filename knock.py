# Copyright 2012 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's quite similar to the one for NOX.  Credit where credit due. :)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pytun import TunTapDevice, IFF_TAP
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
import threading
import subprocess
import struct

log = core.getLogger()

class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  
  tap = None;
  
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection
   
    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.runned = True
    self.let_it_in = False
    
    if Tutorial.tap is None:
      Tutorial.tap = TunTapDevice(flags=IFF_TAP)
      Tutorial.tap.addr = '10.1.1.13'
      Tutorial.tap.netmask = '255.255.255.0'
      Tutorial.tap.mtu=1300
      print "hwaddr for" + Tutorial.tap.name + ": " + str(EthAddr(Tutorial.tap.hwaddr))
      subprocess.check_call("ifconfig " + Tutorial.tap.name + " up", shell=True)
      
    """self.th = threading.Thread(target=self.handle_tap_in)
    self.th.daemon = True
    self.th.start() """
  
  def handle_tap_in(self):
      while True: 
   print "read from tap"
	 packettap = Tutorial.tap.read(Tutorial.tap.mtu+24)
	 for c in core.openflow.connections:
          self.allow_flows_forthis_packet("10.0.0.1",c)
	  
      
  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  def clear_flows(self):
      for c in core.openflow.connections:
          d = of.ofp_flow_mod(command = of.OFPFC_DELETE)
          c.send(d)
          log.info("flows cleared on %s" % c)
   
  def remove_flows(self, src_ip, connection):
	msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
	msg.match.nw_src = src_ip
	connection.send(msg)
	print "here"
	log.info("Src_IP %s Flows removed from connection %s", src_ip, connection)
	
  def deny_flows_forthis_packet(self, src, srcip, connection):
	"""Set this flow with no action so the packet matching this entry will be dropped"""	
	self.remove_flows(srcip, connection)
	
	msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
	msg.priority = 65535
	msg.match.dl_src = src
	msg.match.nw_src = IPAddr(srcip)
	msg.idle_timeout = 1
	msg.hard_timeout = 5
	connection.send(msg)
	log.info("Added deny src %s  srip %s flow-mod to connection %s", src, srcip, connection) 
    
  def allow_flows_forthis_packet(self, srcip, connection):
	"""Allow packet to get in to the network for 15 sec"""
	#remove old flows
	self.remove_flows(src_ip, connection) 

	#set new flow
	msg = of.ofp_flow_mod(command=of.OFPFC_ADD)
	msg.priority = 65535
	msg.match.nw_src = IPAddr(srcip)
	msg.idle_timeout = 1
	msg.hard_timeout = 2
	msg.action=of.ofp_action_output( port = of.OFPP_FLOOD )
	connection.send(msg)
	log.info("Added allow src_ip %s flow-mod to connection %s", srcip, connection) 

  def send_to_knockd(self, packet):
     # remove vlan header and rebuild
      print "Forwarding packet"
      totap = struct.pack('!bbbb', 0, 0, 8, 0) + packet.pack()
      Tutorial.tap.write(totap)

    
  def _handle_PacketIn (self, event):
  
    # Create thread to read from tap and send to switch
    
    if self.runned == True:
	self.clear_flows()
	self.runned = False

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.
    dpid = event.connection.dpid
    connection = event.connection
    inport = event.port
    packet_src = packet.src
    if packet.type == packet.IP_TYPE:
	log.info("ip type")
	ip_packet = packet.payload
	src_ip = ip_packet.srcip
	dst_ip = ip_packet.dstip
	log.info("src ip %s", src_ip)
	if src_ip == "10.0.0.1":
		if self.let_it_in == False:
   			self.deny_flows_forthis_packet(packet_src, src_ip, connection)
			#self.let_it_in = True
			log.info("packet source eth addr: %s ip addr: %s  dst ip: %s connection: %s", packet.src, src_ip, dst_ip, connection )
			self.send_to_knockd(packet)
			

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)

  core.openflow.addListenerByName("ConnectionUp", start_switch)


