//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
// 
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
// 

//TODO: check all err codes for all types, some missing

#include <platdep/sockets.h>
#include <platdep/timeutil.h>
#include "INETDefs.h"
#include <omnetpp.h>
#include "headers/defs.h"
namespace INETFw // load headers into a namespace, to avoid conflicts with platform definitions of the same stuff
{
#include "headers/bsdint.h"
#include "headers/in.h"
#include "headers/in_systm.h"
#include "headers/ip6.h"
#include "headers/ipv6_icmp.h"
}
;
#include "IPv6Serializer.h"
#include "ICMPv6Serializer.h"
#include "PingPayload_m.h"
#include "TCPIPchecksum.h"

#if !defined(_WIN32) && !defined(__WIN32__) && !defined(WIN32) && !defined(__CYGWIN__) && !defined(_WIN64)
#include <netinet/in.h>  // htonl, ntohl, ...
#endif

using namespace INETFw;

#include "ICMPv6Message_m.h"

int ICMPv6Serializer::serialize(const ICMPv6Message *pkt, unsigned char *buf, unsigned int bufsize)
{
    struct icmpv6 *icmp = (struct icmpv6 *) (buf);
    int packetLength;

    packetLength = ICMPV6_MINLEN; //Typ + Code + Prüfusmme = 8bit +8bit +16bit ??
    //packetLength = 32;

    switch (pkt->getType())
    {
        case ICMPv6_UNSPECIFIED: {
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            icmp->icmp_type = ICMPv6_UNSPECIFIED;
            icmp->icmp_code = 0;  //pkt->getCode();
            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_DESTINATION_UNREACHABLE: {
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            ICMPv6DestUnreachableMsg *echo_msg = (ICMPv6DestUnreachableMsg *) (pkt);

            icmp->icmp_type = ICMPv6_DESTINATION_UNREACHABLE;
            icmp->icmp_code = echo_msg->getCode();
            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_PACKET_TOO_BIG: {  //TODO: need verify
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            ICMPv6PacketTooBigMsg *echo_msg = (ICMPv6PacketTooBigMsg *) (pkt);

            icmp->icmp_type = ICMPv6_PACKET_TOO_BIG;
            icmp->icmp_code = echo_msg->getCode();
            //icmp-> ? = echo_msg->getMTU(); //FIXME: here

            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_TIME_EXCEEDED: {  //TODO: need verify

            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            ICMPv6TimeExceededMsg *echo_msg = (ICMPv6TimeExceededMsg *) (pkt);

            icmp->icmp_type = ICMPv6_TIME_EXCEEDED;
            icmp->icmp_code = echo_msg->getCode();
            //icmp->icmp_code = ICMPv6_TIME_EXCEEDED_INTRANSIT;
            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_PARAMETER_PROBLEM: {  //TODO: need verify
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            ICMPv6ParamProblemMsg *echo_msg = (ICMPv6ParamProblemMsg *) (pkt);

            icmp->icmp_type = ICMPv6_PARAMETER_PROBLEM;
            icmp->icmp_code = echo_msg->getCode();
            //icmp->icmp_code = ICMPv6_PARAMETER_PROBLEM_ERR;
            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
//informational msg
        case ICMPv6_ECHO_REQUEST: {
            PingPayload *pp = check_and_cast<PingPayload*>(pkt->getEncapsulatedPacket());
            icmp->icmp_type = ICMPv6_ECHO_REQUEST;
            icmp->icmp_code = 0;
            icmp->icmp_identifier = htons(pp->getOriginatorId());
            icmp->icmp_sequence = htons(pp->getSeqNo());
            unsigned int datalen = (pp->getByteLength() - 4);
            for (unsigned int i = 0; i < datalen; i++)
                if (i < pp->getDataArraySize())
                {
                    icmp->icmp_echodata[i] = pp->getData(i);
                }
                else
                {
                    icmp->icmp_echodata[i] = 'a';
                }
            packetLength += datalen;
            break;
        }
        case ICMPv6_ECHO_REPLY: {
            PingPayload *pp = check_and_cast<PingPayload*>(pkt->getEncapsulatedPacket());
            icmp->icmp_type = ICMPv6_ECHO_REPLY;
            icmp->icmp_code = 0;
            icmp->icmp_identifier = htons(pp->getOriginatorId());
            icmp->icmp_sequence = htons(pp->getSeqNo());
            unsigned int datalen = pp->getDataArraySize();
            for (unsigned int i = 0; i < datalen; i++)
                icmp->icmp_echodata[i] = pp->getData(i);
            packetLength += datalen;
            break;
        }
        case ICMPv6_MLD_QUERY: {
            EV << "Type " << ICMPv6_MLD_QUERY << " not implemented yet!" << endl;
            break;
        }
        case ICMPv6_MLD_REPORT: {
            EV << "Type " << ICMPv6_MLD_REPORT << " not implemented yet!" << endl;
            break;
        }
        case ICMPv6_MLD_DONE: {
            EV << "Type " << ICMPv6_MLD_DONE << " not implemented yet!" << endl;
            break;
        }
        case ICMPv6_ROUTER_SOL: { //TODO: not verified
            IPv6Datagram *ip = new IPv6Datagram();
            ICMPv6Message *msg = (ICMPv6Message *) (pkt);                       //FIXME: no specific msg in ICMPv6Message.msg

            icmp->icmp_type = ICMPv6_ROUTER_SOL;


            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_ROUTER_AD: {  //TODO: not verified
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg
            icmp->icmp_code = 0;   //if Code is in msg than msg->getCode(); //FIXME: d
            icmp->icmp_type = ICMPv6_ROUTER_AD;

            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_NEIGHBOUR_SOL: {
            EV << "Code: " << pkt->getCode() << "Type: " << pkt->getType() << endl; //only Test output, can delete
            IPv6Datagram *ip = new IPv6Datagram();
            //icmp->icmp_dun.id_neighbor.idn_addr  //FIXME: maybe use this ...

            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg
            //icmp->icmp_code = 0;   //if Code is in msg than msg->getCode();
            icmp->icmp_type = ICMPv6_NEIGHBOUR_SOL;
            icmp->icmp_code = pkt->getCode();
            icmp->icmp_cksum = pkt->getByteLength();


            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN); //icmp->icmp_dun...neighbor ... ?? check is empty from above or not
            break;
        }

        case ICMPv6_NEIGHBOUR_AD: {//TODO: not verified
            //IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());
            EV << "Neighbour_AD. Code: " << pkt->getCode() << "Type: " << pkt->getType() << endl;
            IPv6Datagram *ip = new IPv6Datagram();
            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg
            //icmp->icmp_code = 0;   //if Code is in msg than msg->getCode(); //FIXME: d
            icmp->icmp_type = ICMPv6_NEIGHBOUR_AD;

            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case ICMPv6_REDIRECT: {  //TODO: not verified
            IPv6Datagram *ip = check_and_cast<IPv6Datagram*>(pkt->getEncapsulatedPacket());

            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg
            icmp->icmp_code = 0;   //if Code is in msg than msg->getCode(); //FIXME: d
            icmp->icmp_type = ICMPv6_REDIRECT;

            packetLength += IPv6Serializer().serialize(ip, (unsigned char *) icmp->icmp_echodata,
                    bufsize - ICMPV6_MINLEN);
            break;
        }
        case 138:
        case 139:
        case 140:
        case 143:
        case 150: {
            packetLength = 0;
            EV << "ICMP packet: type " << pkt->getType() << " is not implemented yet.";
            break;
        }

        default: {
            packetLength = 0;
            EV << "Can not serialize ICMP packet: type " << pkt->getType() << " not supported.";
            break;
        }
    }
    icmp->icmp_cksum = TCPIPchecksum::checksum(buf, packetLength);  //TODO: not verified
    return packetLength;
}

void ICMPv6Serializer::parse(const unsigned char *buf, unsigned int bufsize, ICMPv6Message *pkt)
{
    struct icmpv6 *icmp = (struct icmpv6*) buf;

    switch (icmp->icmp_type)
    {
        case ICMPv6_ECHO_REQUEST: {

            pkt->setType(ICMPv6_ECHO_REQUEST);
            ICMPv6EchoRequestMsg *echo_msg = check_and_cast<ICMPv6EchoRequestMsg *>(pkt);

            echo_msg->setCode(0);
            echo_msg->setIdentifier(0);
            echo_msg->setSeqNumber(0);
            echo_msg->setByteLength(4);

            PingPayload *pp;
            char name[32];

            sprintf(name, "ping%d", ntohs(icmp->icmp_sequence));
            pp = new PingPayload(name);
            //pp->setOriginatorId(ntohs(icmp->icmp_h.ih_idseq.ihs_id));
            //pp->setSeqNo(ntohs(icmp->icmp_h.ih_idseq.ihs_seq));
            pp->setOriginatorId(ntohs(icmp->icmp_identifier));
            pp->setSeqNo(ntohs(icmp->icmp_sequence));
            pp->setByteLength(bufsize - 4);
            pp->setDataArraySize(bufsize - ICMPV6_MINLEN);
            for (unsigned int i = 0; i < bufsize - ICMPV6_MINLEN; i++)
            {
                pp->setData(i, icmp->icmp_echodata[i]);
            }
            echo_msg->encapsulate(pp);
            echo_msg->setName(pp->getName());
            break;
        }
        case ICMPv6_ECHO_REPLY: {

            pkt->setType(ICMPv6_ECHO_REPLY);
            ICMPv6EchoReplyMsg *echo_msg = check_and_cast<ICMPv6EchoReplyMsg *>(pkt);

            echo_msg->setCode(0);
            echo_msg->setIdentifier(0);
            echo_msg->setSeqNumber(0);
            echo_msg->setByteLength(4);

            PingPayload *pp;
            char name[32];

            sprintf(name, "ping%d-reply", ntohs(icmp->icmp_sequence));
            pp = new PingPayload(name);
            pp->setOriginatorId(ntohs(icmp->icmp_identifier));
            pp->setSeqNo(ntohs(icmp->icmp_sequence));
            pp->setByteLength(bufsize - 4);
            pp->setDataArraySize(bufsize - ICMPV6_MINLEN);
            for (unsigned int i = 0; i < bufsize - ICMPV6_MINLEN; i++)
                pp->setData(i, icmp->icmp_echodata[i]);
            echo_msg->encapsulate(pp);
            echo_msg->setName(pp->getName());
            break;
        }

        case ICMPv6_NEIGHBOUR_SOL: {
            IPv6Datagram *ip = new IPv6Datagram();
            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg
            ICMPv6Message *msg = check_and_cast<ICMPv6Message *>(pkt);

            msg->setType(ICMPv6_NEIGHBOUR_SOL);  //generische lsg: msg->setType(icmp->icmp_type);
            msg->setByteLength(icmp->icmp_cksum); //TODO: verifiy
            msg->setCode(icmp->icmp_code);
            //msg->setCode(0);
            //msg->setByteLength(4);
            ip->setName("NEIGHBOUR_SOL");

            ip->encapsulate(msg); //missing some issues here, dup() ?

            break;
        }

        case ICMPv6_NEIGHBOUR_AD: {
            IPv6Datagram *ip = new IPv6Datagram();
            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg

            pkt->setType(ICMPv6_NEIGHBOUR_AD);
            pkt->setCode(0);
            pkt->setByteLength(4);
            ip->setName("NEIGHBOUR_AD");

            ip->encapsulate(pkt); //missing some issues here, dup() ?
            break;
        }

        case ICMPv6_REDIRECT: {
            IPv6Datagram *ip = new IPv6Datagram();
            //ICMPv6Message *msg = (ICMPv6Message *) (pkt);  //FIXME: no specific msg in ICMPv6Message.msg

            pkt->setType(ICMPv6_REDIRECT);
            pkt->setCode(0);
            pkt->setByteLength(4);
            ip->setName("REDIRECT");

            ip->encapsulate(pkt); //missing some issues here, dup() ?
            break;
        }
        case ICMPv6_DESTINATION_UNREACHABLE: {
            IPv6Datagram *ip = new IPv6Datagram();
            ICMPv6DestUnreachableMsg *msg = check_and_cast<ICMPv6DestUnreachableMsg *>(pkt);

            msg->setType(ICMPv6_DESTINATION_UNREACHABLE);
            msg->setCode(0);            //TODO: @all setCode is set in pkt? verifiy
            msg->setByteLength(4);
            ip->setName("DESTINATION_UNREACHABLE");

            ip->encapsulate(msg); //missing some issues here, dup() ?
            break;
        }
        case ICMPv6_PACKET_TOO_BIG: {
            IPv6Datagram *ip = new IPv6Datagram();
            ICMPv6PacketTooBigMsg *msg = check_and_cast<ICMPv6PacketTooBigMsg *>(pkt);

            msg->setType(ICMPv6_PACKET_TOO_BIG);
            msg->setCode(0);            //TODO: @all setCode is set in pkt? verifiy
            msg->setMTU(1280);          //FIXME: to which value it should set?
            msg->setByteLength(4);
            ip->setName("PACKET_TOO_BIG");

            ip->encapsulate(msg); //missing some issues here, dup() ?
            break;
        }
        case ICMPv6_TIME_EXCEEDED: {
            IPv6Datagram *ip = new IPv6Datagram();
            ICMPv6TimeExceededMsg *msg = check_and_cast<ICMPv6TimeExceededMsg *>(pkt);

            msg->setType(ICMPv6_TIME_EXCEEDED);
            msg->setCode(0);            //TODO: @all setCode is set in pkt? verifiy
            msg->setByteLength(4);
            ip->setName("ICMPv6_TIME_EXCEEDED");

            ip->encapsulate(msg); //missing some issues here, dup() ?
            break;
        }
        case ICMPv6_PARAMETER_PROBLEM: {
            IPv6Datagram *ip = new IPv6Datagram();
            ICMPv6TimeExceededMsg *msg = check_and_cast<ICMPv6TimeExceededMsg *>(pkt);

            msg->setType(ICMPv6_TIME_EXCEEDED);
            msg->setCode(0);            //TODO: @all setCode is set in pkt? verifiy
            msg->setByteLength(4);
            ip->setName("ICMPv6_TIME_EXCEEDED");

            ip->encapsulate(msg); //missing some issues here, dup() ?
            break;
        }

        default: {
            EV << "Can not create ICMP packet: type " << icmp->icmp_type << " not supported.";
            break;
        }
    }
}

