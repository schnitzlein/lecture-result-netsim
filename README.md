# lecture-result-netsim
OMNeT++ INET IPv6 PCAP Reader Writer

It is a prototype and still unfinished, wireshark eg. will see checksum errors.
But packet capturing for ipv6 packets work.


In INET Framework is as far as i can see no IPv6 PCAP-Reader-Writer.
Result of lecture-seminar in 2014/2015 @BTU Cottbus was a prototype of it.
With information and advice of the lecturer M. Kirsche was it possible to create this.

There are some new files in inet/src/util/headerserialzier/ipv6
   /icmpv6serializier
...parser in ipv6serializer
...headers/ipv6_icmp.h
... and copy from example apps ipv6.h

There are issues in the files and checksum calculation until now not fixed!
This is a prototype version of ipv6 packet capturing.

_____________________________________________________________________________________

HOWTo:

where to put the code, the directory ipv6: inet/src/util/headerserialzier/ipv6

add this piece of code in PcapRecorder.cc 
...
#ifdef WITH_IPv6
#include "IPv6Datagram.h"
#include <ICMPv6.h> //added
#endif
...

add this piece of code @ipv6 exmaple, in a .ned file or add graphically PcapRecorder
...
pcapRecorder: PcapRecorder {
            @display("p=31,275");
        }
...

Run the example network,
check the result directory and you have a pcap file, hopefully
_____________________________________________________________________________________

absolutley no warranty! no test on newer INET version. maybe ... if time ...


