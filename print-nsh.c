/* Copyright (c) 2015, bugyo
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met: 
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <netdissect-stdinc.h>

#include "netdissect.h"
#include "extract.h"

/*
 * NSH, draft-ietf-sfc-nsh-01 Network Service Header
 */

void
nsh_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
    int nhlen, n;
    uint8_t ver;
    uint8_t flag_o;
    uint8_t flag_c;
    uint8_t length;
    uint8_t md_type;
    uint8_t next_protocol;
    uint32_t service_path_id;
    uint8_t service_index;
    uint32_t ctx;

    if (len < 8) {
        ND_PRINT((ndo, "[|NSH]"));
        return;
    }

    ver = (uint8_t)(*bp >> 6);
    flag_o = *bp & 0x20;
    flag_c = *bp & 0x10;
    bp += 1;
    length = *bp;
    bp += 1;
    md_type = *bp;
    bp += 1;
    next_protocol = *bp;
    bp += 1;
    service_path_id = EXTRACT_24BITS(bp);
    bp += 3;
    service_index = *bp;
    bp += 1;

    nhlen = length << 2;

    ND_PRINT((ndo, "NSH, "));
    if (1 < ndo->ndo_vflag) {
        ND_PRINT((ndo, "ver %d, ", ver));
    }
    ND_PRINT((ndo, "flags [%s%s], ", flag_o ? "O" : "", flag_c ? "C" : ""));
    if (2 < ndo->ndo_vflag) {
        ND_PRINT((ndo, "length %d, ", length));
        ND_PRINT((ndo, "MD Type 0x%x, ", md_type));
    }
    if (1 < ndo->ndo_vflag) {
        ND_PRINT((ndo, "Next Protocol 0x%x, ", next_protocol));
    }
    ND_PRINT((ndo, "Service Path ID 0x%06x, ", service_path_id));
    ND_PRINT((ndo, "Service Index 0x%x", service_index));


    for (n = 0; n < (nhlen - 8); n += 4) {
	ctx = EXTRACT_32BITS(bp);
	bp += 4;
	if (2 < ndo->ndo_vflag) {
	    ND_PRINT((ndo, "\n        Context[%02d]: 0x%08x", n / 4, ctx));
	}
    }
    ND_PRINT((ndo, ndo->ndo_vflag ? "\n    " : ": "));

    switch (next_protocol) {
    case 0x1:
        ip_print(ndo, bp, len - nhlen);
        break;
    case 0x2:
        ip6_print(ndo, bp, len - nhlen);
        break;
    case 0x3:
        ether_print(ndo, bp, len - nhlen, len - nhlen, NULL, NULL);
        break;
    default:
        ND_PRINT((ndo, "[|NSH]"));
        return;
    }
}

