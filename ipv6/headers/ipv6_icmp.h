/*
 * ipv6_icmp.h
 *
 *  Created on: Jan 6, 2015
 *      Author: C
 */

#ifndef IPV6_ICMP_H_
#define IPV6_ICMP_H_

#include <in_systm.h>
#include <in.h>
#include <ip6.h>

/*
 * Internet Control Message Protocol (ICMPv6)
 * Per RFC 4443
 *          with Neighbor Discovery for IP Version 6 (IPv6) RFC 2461
 */

//FIXME strange OMNeT++ error from empty structs... see //

/*
 * Structure of an icmpv6 header.
 *
 * icmpv6 { u_int8, u_int8, u_int16 }
 * icmpv6 { type,   code , checksum } + ICMPv6 msg
 *
 * //usr/include/x86_x64-linux-gnu/sys/types.h
 */
struct icmpv6 {
    u_char icmp_type; /* type of message, see below */
    u_char icmp_code; /* type sub code */
    u_short icmp_cksum; /* ones complement cksum of struct */

    //ICMPv6 msg
    union {
        u_int32_t ih_reserved;
        struct ih_idseq {                   // for ICMPv6 Informational Messages
            u_int16_t ihs_id; /* identification */
            u_int16_t ihs_seq; /* sequencenumber */
        } ih_idseq;
        struct ih_radv {
            u_int8_t ihr_hoplimit;
            u_int8_t ihr_bits;
            u_int16_t ihr_lifetime;
        } ih_radv;
    } icmp_h;
/* ICMPv6 error msg */
#define icmp_unused icmp_h.ih_reserved        /* used by: Destination Unreachable Message, Time Exceeded Message */
#define icmp_nexthopmtu icmp_h.ih_reserved    /* Packet Too Big Message */
#define icmp_pointer icmp_h.ih_reserved       /* Parameter Problem Message */
/* ICMPv6 error msg */

/* ICMPv6 informational msg */
#define icmp_identifier icmp_h.ih_idseq.ihs_id    /* Echo Request Message, Echo Reply Message */
#define icmp_sequence icmp_h.ih_idseq.ihs_seq     /* Echo Request Message, Echo Reply Message */
/* ICMPv6 informational msg */

#define icmp_grpdelay icmp_h.ih_idseq.ihs_id
#define icmp_grpunused icmp_h.ih_idseq.ihs_seq

#define icmp_radvhop icmp_h.ih_radv.ihr_hoplimit
#define icmp_radvbits icmp_h.ih_radv.ihr_bits
#define icmp_radvlifetime icmp_h.ih_radv.ihr_lifetime
    union
        {
          struct
        {
          struct in6_addr ido_ipv6;  //FIXME: was ipv6
          u_int8_t ido_remaining[1];
        } id_offending;
          u_int8_t id_data[1];
          struct
        {
          struct in6_addr idn_addr;
          u_int8_t idn_ext[1];
        } id_neighbor;
          struct
        {
          struct in6_addr idr_addr1;
          struct in6_addr idr_addr2;
          u_int8_t idr_ext[1];
        } id_redirect;
          struct
        {
          u_int32_t ida_reachable;
          u_int32_t ida_retrans;
          u_int8_t ida_opt[1];
        } id_radv;
        } icmp_dun;
    #define icmp_offending icmp_dun.id_offending
    #define icmp_ipv6 icmp_dun.id_offending.ido_ipv6 //FIXME: missing see above

    #define icmp_echodata icmp_dun.id_data

    #define icmp_grpaddr icmp_dun.id_neighbor.idn_addr

    #define icmp_radvreach icmp_dun.id_radv.ida_reachable
    #define icmp_radvretrans icmp_dun.id_radv.ida_retrans
    #define icmp_radvext icmp_dun.id_radv.ida_opt

    #define icmp_nsoltarg icmp_dun.id_neighbor.idn_addr
    #define icmp_nsolext icmp_dun.id_neighbor.idn_ext
    #define icmp_nadvaddr icmp_dun.id_neighbor.idn_addr
    #define icmp_nadvext icmp_dun.id_neighbor.idn_ext

    #define icmp_redirtarg icmp_dun.id_redirect.idr_addr1
    #define icmp_redirdest icmp_dun.id_redirect.idr_addr2
    #define icmp_redirext icmp_dun.id_redirect.idr_ext
};

/*
 * ICMPv6 extension constants.
 */

#define EXT_SOURCELINK 1
#define EXT_TARGETLINK 2
#define EXT_PREFIX 3
#define EXT_REDIR 4
#define EXT_MTU 5

/*
 * Extension structures for IPv6 discovery messages.
 */

struct icmp_exthdr    /* Generic extension */   //FIXME: should be ip6_ext from ip6.h
{
  u_int8_t ext_id;
  u_int8_t ext_length;    /* Length is 8 * this field, 0 is invalid. */
  u_int8_t ext_data[6];   /* Padded to 8 bytes. */
};

struct ext_prefinfo    /* Prefix information */
{
  u_int8_t pre_extid;
  u_int8_t pre_length;

  u_int8_t pre_prefixsize;
  u_int8_t pre_bits;

  u_int32_t pre_valid;
  u_int32_t pre_preferred;
  u_int32_t pre_reserved;

  struct in6_addr pre_prefix;
};

/*
 * Values for pre_bits
 */
#define ICMPV6_PREFIX_ONLINK 0x80
#define ICMPV6_PREFIX_AUTO 0x40

struct ext_redir    /* Redirected header */
{
  u_int8_t rd_extid;
  u_int8_t rd_length;
  u_int8_t rd_reserved[6];
  struct ip6_hdr rd_header;
};

struct ext_mtu      /* Recommended link MTU. */
{
  u_int8_t mtu_extid;
  u_int8_t mtu_length;
  u_int16_t mtu_reserved;
  u_int32_t mtu_mtu;
};

/*
 * Constants
 */

/*
 * Lower bounds on packet lengths for various types.
 * For the error advice packets must first insure that the
 * packet is large enought to contain the returned ip header.
 * Only then can we do the check to see if enough bits of packet
 * data have been returned, since we need to check the returned
 * ipv6 header length.
 */
#define ICMPV6_MINLEN   8               /* abs minimum */
#define ICMPV6_TSLEN    (8 + 3 * sizeof (n_time))   /* timestamp */
#define ICMPV6_NADVMINLEN 24    /* min neighbor advertisement */
#define ICMPV6_NSOLMINLEN 24    /* min neighbor solicit */
#define ICMPV6_RADVMINLEN 16    /* min router advertisement */
#define ICMPV6_RSOLMINLEN 8    /* min router solicit */
#define ICMPV6_HLPMINLEN (8 + sizeof(struct ipv6) + 8)  /* HLP demux len. */
#define ICMPV6_MAXLEN     576   /* This should be whatever IPV6_MINMTU
                   will be.  I take this to be the WHOLE
                   packet, including IPv6 header, and any
                   IPv6 options before the ICMP message. */

/* Defined this way to save some HTONL cycles on little-endian boxes. */
#if BYTE_ORDER == BIG_ENDIAN
#define           ICMPV6_NEIGHBORADV_RTR   0x80000000  /* Router flag. */
#define           ICMPV6_NEIGHBORADV_SOL   0x40000000  /* Solicited flag. */
#define           ICMPV6_NEIGHBORADV_OVERRIDE 0x20000000 /* Override flag. */
#else  /* BYTE_ORDER == LITTLE_ENDIAN */
#define           ICMPV6_NEIGHBORADV_RTR   0x80  /* Router flag. */
#define           ICMPV6_NEIGHBORADV_SOL   0x40  /* Solicited flag. */
#define           ICMPV6_NEIGHBORADV_OVERRIDE 0x20 /* Override flag. */
#endif





/*
 * Definition of type and code field values from RFC 4443
 */

/* ICMPv6 type
 * > 1 error msg, > 127 informational msg
 * from ICMPv6Message.msg,
 * read more @ http://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
 */
/*
#define ICMPv6_UNSPECIFIED             0
#define ICMPv6_DESTINATION_UNREACHABLE 1 /* dest unreachable */
//#define ICMPv6_PACKET_TOO_BIG          2        /* Packet too big */
//#define ICMPv6_TIME_EXCEEDED           3        /* Time Exceeded Message */
/*#define ICMPv6_PARAMETER_PROBLEM       4
#define ICMPv6_RESERVED_ERR_MSG 127
/*
 * ICMPv6 informational messages codes
 */
/*#define ICMPv6_ECHO_REQUEST    128
#define ICMPv6_ECHO_REPLY      129
#define ICMPv6_MLD_QUERY       130
#define ICMPv6_MLD_REPORT      131
#define ICMPv6_MLD_DONE        132
#define ICMPv6_ROUTER_SOL      133
#define ICMPv6_ROUTER_AD       134
#define ICMPv6_NEIGHBOUR_SOL   135
#define ICMPv6_NEIGHBOUR_AD    136
#define ICMPv6_REDIRECT        137
#define ICMPv6_ROUTER_RENUMBERING 138 //missing in ipv6.msg
#define ICMPv6_NODE_QUERY 139         //missing in ipv6.msg
#define ICMPv6_NODE_RESPONSE 140      //missing in ipv6.msg
//141 missing
//142 missing
#define ICMPv6_MLDv2_REPORT 143*/
//144 missing
//145 missing
//146 missing
//147 missing
//148 missing
//149 missing
//#define ICMPv6_EXPERIMENTAL_MOBILITY 150 //Zarrar Yousaf 02.08.07 (FMIPv6 Implementation)
/* ICMPv6 type  */

/* sub error codes */
#define ICMPV6_UNREACH_NOROUTE       0                  /* No route to dest. */
#define ICMPV6_UNREACH_ADMIN         1                  /* Admin. prohibited */
#define ICMPV6_UNREACH_NOTNEIGHBOR   2              /* For strict source routing. */
#define ICMPV6_UNREACH_ADDRESS       3                  /* Address unreach. */
#define ICMPV6_UNREACH_PORT          4

#define ICMPv6_TIME_EXCEEDED_INTRANSIT 0
#define ICMPv6_TIME_EXCEEDED_REASSM    1

#define ICMPv6_PARAMETER_PROBLEM_ERR     0       /* Erroneous header field encountered */
#define ICMPv6_PARAMETER_PROBLEM_NEXTHDR 1       /* Unrecognized Next Header type encountered */
#define ICMPv6_PARAMETER_PROBLEM_BADOPT  2       /* Unrecognized IPv6 option encountered */


#endif /* IPV6_ICMP_H_ */
