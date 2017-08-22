#!/usr/bin/python
import argparse
from scapy.all import *


# https://tools.ietf.org/html/draft-foschiano-erspan-00#section-4.1
class ERSPAN(Packet):
 name = "ERSPAN"
 fields_desc = [BitField("version", 1, 4),
                   BitField("vlan", 0, 12),
                   BitField("cos", 0, 3),
                   BitField("encap", 0, 2),
                   BitField("truncated", 0, 1),
                   BitField("span_id", 0, 10),
                   BitField("reserved", 0, 12),
                   BitField("if_index", 0, 20)]

def fill_packets(args,packet,packet_num,layer):

 erspan_packet = Ether()/IP(dst=args.erspan_l3dest)/GRE(flags=0x1000, proto=0x88be)/ERSPAN()/packet

 if Dot1Q in packet:
  erspan_packet[ERSPAN].encap=3
  erspan_packet[ERSPAN].cos=packet[Dot1Q].prio
  erspan_packet[ERSPAN].vlan=packet[Dot1Q].vlan

 else:
  erspan_packet[ERSPAN].encap=0

 if layer == 2:

  if args.erspan_l2src:
    erspan_packet[Ether].src = args.erspan_l2src

  if args.erspan_l2dest:
    erspan_packet[Ether].dst = args.erspan_l2dest

  if args.erspan_l3src:
   erspan_packet[Ether][IP].src = args.erspan_l3src

  if args.erspan_gre_seq:
   erspan_packet[Ether][IP][GRE].seqnum_present = 1
   erspan_packet[Ether][IP][GRE].seqence_number = packet_num

  if args.erspan_id:
   erspan_packet[Ether][IP][GRE][ERSPAN].span_id = args.erspan_id

  if args.erspan_IF:
   erspan_packet[Ether][IP][GRE][ERSPAN].if_index = args.erspan_IF

 else:

  if args.erspan_l3src:
   erspan_packet[IP].src = args.erspan_l3src

  if args.erspan_gre_seq:
   erspan_packet[IP][GRE].seqnum_present = int(1)
   erspan_packet[IP][GRE].seqence_number = int(packet_num)

  if args.erspan_id:
   erspan_packet[IP][GRE][ERSPAN].span_id = int(args.erspan_id)

  if args.erspan_IF:
   erspan_packet[IP][GRE][ERSPAN].if_index = int(args.erspan_IF)

 return erspan_packet

parser = argparse.ArgumentParser()
parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
optional = parser.add_argument_group('optional arguments')

required.add_argument("--interface","-i",type=str,help="the interface to capture on")
required.add_argument("--erspan_l3dest","-l3dst",type=str,help="the ERSPAN L3 destination")

optional.add_argument("--filter","-f",type=str,help="capture filter",default="")
optional.add_argument("--count","-c",type=int,help="number of packets to capture",default=0)
optional.add_argument("--erspan_l3src","-l3src",help="the ERSPAN L3 source",default="")
optional.add_argument("--erspan_l2dest","-l2dst",help="the ERSPAN L2 destination",default="")
optional.add_argument("--erspan_l2src","-l2src",help="the ERSPAN L2 source",default="")
optional.add_argument("--erspan_egress_IF","-ei",help="the interface to send ERSPAN packets out",default="")
optional.add_argument("--erspan_gre_seq","-egs",type=int,help="do you want GRE sequence numbers? 0 or 1",default="1")
optional.add_argument("--erspan_id","-essd",type=int,help="ERSPAN session ID",default="1")
optional.add_argument("--erspan_IF","-eifid",type=int,help="ERSPAN IF ID",default="1")

args=parser.parse_args()

if __name__ == '__main__':

 if not ( args.interface and args.erspan_l3dest ):
  print "need interface and ERSPAN destination at least. use -h for options"
  quit()

 if not args.filter:
  if not args.count:
   sniffed=sniff(iface=args.interface)
  else:
   sniffed=sniff(iface=args.interface,count=args.count)
 else:
  if not args.count:
   sniffed=sniff(iface=args.interface,filter=args.filter)
  else:
   sniffed=sniff(iface=args.interface,count=args.count,filter=args.filter)

 i=0
 for packet in sniffed:
  i+=1
  pad = Padding()
  pad.load = '\x00' * 4 # FCS
  packet=packet/pad
  if ( args.erspan_l2dest or args.erspan_l2src or args.erspan_egress_IF ):
   layer = 2
   erspan_packet=fill_packets(args,packet,i,layer)
   sendp(erspan_packet,iface=args.erspan_egress_IF)


  else:
   layer = 3
   erspan_packet=fill_packets(args,packet,i,layer)
   send(erspan_packet)
