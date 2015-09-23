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
// created by Christoph Schwalbe

#ifndef ICMPV6SERIALIZER_H_
#define ICMPV6SERIALIZER_H_

#include "ICMPv6Message_m.h"


/**
 * Converts between IPv6_ICMPMessage and binary (network byte order) ICMPv6 header.
 */
class ICMPv6Serializer {

public:

    ICMPv6Serializer() { }
    //virtual ~ICMPv6Serializer();

    /**
     * Serializes an ICMPv6Message for transmission on the wire.
     * Returns the length of data written into buffer.
     */
    int serialize(const ICMPv6Message *pkt, unsigned char *buf,
            unsigned int bufsize);

    /**
     * Puts a packet sniffed from the wire into an ICMPv6Message.
     */
    void parse(const unsigned char *buf, unsigned int bufsize,
            ICMPv6Message *pkt);
};

#endif /* ICMPV6SERIALIZER_H_ */
