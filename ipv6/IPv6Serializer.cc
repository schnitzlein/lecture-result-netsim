//
// Copyright (C) 2013 Irene Ruengeler
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include <algorithm> // std::min
#include <platdep/sockets.h>

#include "headers/defs.h"

namespace INET6Fw // load headers into a namespace, to avoid conflicts with platform definitions of the same stuff
{
#include "headers/bsdint.h"
#include "headers/in.h"
#include "headers/in_systm.h"
#include "headers/ip6.h"
}
;

#include "IPv6Serializer.h"
#include "ICMPv6Serializer.h"
#include "IPProtocolId_m.h"

#ifdef WITH_UDP
#include "UDPSerializer.h"
#endif

#ifdef WITH_SCTP
#include "SCTPSerializer.h"
#endif

#include "TCPIPchecksum.h"

#ifdef WITH_TCP_COMMON
#include "TCPSegment.h"
#include "TCPSerializer.h"
#endif

#if defined(_MSC_VER)
#undef s_addr   /* MSVC #definition interferes with us */
#endif

#if !defined(_WIN32) && !defined(__WIN32__) && !defined(WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)
#include <netinet/in.h>  // htonl, ntohl, ...
#endif

// This in_addr field is defined as a macro in Windows and Solaris, which interferes with us
#undef s_addr

using namespace INET6Fw;

int IPv6Serializer::serialize(const IPv6Datagram *dgram, unsigned char *buf, unsigned int bufsize)
{
    int packetLength, i;
    uint32_t flowinfo;

    EV << "Serialize IPv6 packet\n";

    struct ip6_hdr *ip6h = (struct ip6_hdr *) buf;

    flowinfo = 0x06;
    flowinfo <<= 8;
    flowinfo |= dgram->getTrafficClass();
    flowinfo <<= 20;
    flowinfo |= dgram->getFlowLabel();
    ip6h->ip6_flow = htonl(flowinfo);
    ip6h->ip6_hlim = htons(dgram->getHopLimit());

    ip6h->ip6_nxt = dgram->getTransportProtocol();

    for (i = 0; i < 4; i++)
    {
        ip6h->ip6_src.__u6_addr.__u6_addr32[i] = htonl(dgram->getSrcAddress().words()[i]);
    }
    for (i = 0; i < 4; i++)
    {
        ip6h->ip6_dst.__u6_addr.__u6_addr32[i] = htonl(dgram->getDestAddress().words()[i]);
    }

    cMessage *encapPacket = dgram->getEncapsulatedPacket();

    switch (dgram->getTransportProtocol())
    {
        case IP_PROT_IPv6_ICMP:  //FIXME: checksum error, some case not implemented yet
            packetLength += ICMPv6Serializer().serialize(check_and_cast<ICMPv6Message *>(encapPacket),
                    buf + IPv6_HEADER_BYTES, bufsize - IPv6_HEADER_BYTES);
            break;
#ifdef WITH_UDP
        case IP_PROT_UDP:
            packetLength = UDPSerializer().serialize(check_and_cast<UDPPacket *>(encapPacket), buf + IPv6_HEADER_BYTES,
                    bufsize - IPv6_HEADER_BYTES);
            break;
#endif

#ifdef WITH_SCTP
        case IP_PROT_SCTP:
            packetLength = SCTPSerializer().serialize(check_and_cast<SCTPMessage *>(encapPacket),
                    buf + IPv6_HEADER_BYTES, bufsize - IPv6_HEADER_BYTES);
            break;
#endif

#ifdef WITH_TCP_COMMON
        case IP_PROT_TCP:
            packetLength = TCPSerializer().serialize(check_and_cast<TCPSegment *>(encapPacket), buf + IPv6_HEADER_BYTES,
                    bufsize - IPv6_HEADER_BYTES, dgram->getSrcAddress(), dgram->getDestAddress());
            break;
#endif

        default:
            printf("IPv6Serializer: cannot serialize protocol %d\n", dgram->getTransportProtocol());
            return -1;
    }

    ip6h->ip6_plen = htons(packetLength);

    return (packetLength + IPv6_HEADER_BYTES);
}

//TODO: verifiy, work only with capturing packet cut short!!!!!!!!
void IPv6Serializer::parse(const unsigned char *buf, unsigned int bufsize, IPv6Datagram *dest)
{
    const struct ip6_hdr *ip = (const struct ip6_hdr *) buf;
    unsigned int totalLength, headerLength;

//TODO: make things for ipv6
    //dest->setVersion(ip6_vfc); //setVersion function - missing in higher class
    //IPV6_VERSION

    //dest->setSrcAddress(IPv6Address(ip->ip6_src)); //does this work?!? //FIXME: easier cast?
    //dest->setDestAddress(IPv6Address(ip->ip6_dst));

    // Address IPv6 set manually
    #define src_part ip->ip6_src.__u6_addr.__u6_addr32
    #define dst_part ip->ip6_dst.__u6_addr.__u6_addr32
    IPv6Address src;
    //= new IPv6Address();
    src.set(src_part[0],src_part[1],src_part[2],src_part[3]);

    IPv6Address dst;
    //= new IPv6Address();
    dst.set(dst_part[0],dst_part[1],dst_part[2],dst_part[3]);


    dest->setSrcAddress(src);
    dest->setDestAddress(dst);
    dest->setTransportProtocol(ip->ip6_nxt);        //dest->setTransportProtocol(ip->ip6_ctlun.ip6_un1.ip6_un1_nxt);
    dest->setFlowLabel(ip->ip6_flow);
    dest->setHopLimit(ip->ip6_hlim);


    totalLength = ntohs(ip->ip6_ctlun.ip6_un1.ip6_un1_plen);  //payload length
    //headerLength = ip->...; //FIXME length is ??
    headerLength = IPv6_HEADER_BYTES; //dummy

    //ICMPv6 ist 8bit NDP Nachricht, 8bit Code der NDP, 16 Prüfsumme
    //Pseudoheader = 128 bit + 128 bit + ICMPv6Header+ICMPv6Payload + NextHeader

    if (headerLength > (unsigned int) IPv6_HEADER_BYTES)
    {
        EV << "Handling an captured IPv6 packet with options. Dropping the options.\n";
    }
    if (totalLength > bufsize) //Payload too big or Buffer too small.
    {
        EV << "Can not handle IPv6 packet of total length " << totalLength << "(captured only " << bufsize
                << " bytes).\n";
    }
    dest->setByteLength(IPv6_HEADER_BYTES);

    cPacket *encapPacket = NULL;
    unsigned int encapLength = std::min(totalLength, bufsize) - headerLength;

    switch (dest->getTransportProtocol())
    {
        case IP_PROT_IPv6_ICMP: {
            encapPacket = new ICMPv6Message("icmpv6-from-wire");
            ICMPv6Serializer().parse(buf + headerLength, encapLength, (ICMPv6Message *) encapPacket);
            break;
        }

#ifdef WITH_UDP
        case IP_PROT_UDP:
            encapPacket = new UDPPacket("udp-from-wire");
            UDPSerializer().parse(buf + headerLength, encapLength, (UDPPacket *) encapPacket);
            break;
#endif

#ifdef WITH_SCTP
        case IP_PROT_SCTP:
            encapPacket = new SCTPMessage("sctp-from-wire");
            SCTPSerializer().parse(buf + headerLength, encapLength, (SCTPMessage *) encapPacket);
            break;
#endif

#ifdef WITH_TCP_COMMON
        case IP_PROT_TCP:
            encapPacket = new TCPSegment("tcp-from-wire");
            TCPSerializer().parse(buf + headerLength, encapLength, (TCPSegment *) encapPacket, true);
            break;
#endif

            /* TODO here case:
             * IP_PROT_IPv6EXT_HOP = 0,
             IP_PROT_IPv6EXT_DEST = 60,
             IP_PROT_IPv6EXT_ROUTING = 43,
             IP_PROT_IPv6EXT_FRAGMENT = 44,
             IP_PROT_IPv6EXT_AUTH = 51,
             IP_PROT_IPv6EXT_ESP = 50,
             IP_PROT_IPv6EXT_MOB = 135
             */

        default: {
            throw cRuntimeError("IPv6Serializer: cannot parse protocol %d", dest->getTransportProtocol());
        }
            ASSERT(encapPacket);
            dest->encapsulate(encapPacket);
            dest->setName(encapPacket->getName());
    }//switch
}

