
/* dump ovstack */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include "interface.h"
#include <extract.h>


/* overlay header */
/*
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |    version    |      app      |      TTL      |     Flags     |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |          Virtual Network Identifier (VNI)     |      rsv      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                              Hash                             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                  overlay destination node address             |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                    overlay source node address                |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


void
ovstack_print (netdissect_options * ndo, const u_char *bp, u_int len)
{
	uint8_t version, app, ttl, flags;
	uint32_t vni, hash, dst, src;
	char s[16], d[16];

	if (len < 20) {
		ND_PRINT ((ndo, "[|ovstack]"));
		return;
	}

	ND_PRINT ((ndo, "ovstack\n"));
	version = *bp;
	bp++;
	app = *bp;
	bp++;
	ttl = *bp;
	bp++;
	flags = *bp;
	bp++;

	vni = *((uint32_t *) bp);
	vni = ntohl (vni) >> 8;
	bp += 4;

	hash = *((uint32_t *) bp);
	bp += 4;

	dst = *((uint32_t *) bp);
	bp += 4;
	src = *((uint32_t *) bp);
	bp += 4;

	inet_ntop (AF_INET, &src, s, sizeof (s));
	inet_ntop (AF_INET, &dst, d, sizeof (d));

	ND_PRINT ((ndo,
		   "version %u, app %u, ttl %u, flag %u, vni %u, hash %u, ",
		   version, app, ttl, flags, vni, hash));
	ND_PRINT ((ndo, "src %s, dst %s\n", s, d));

	if (app == 7)
		ether_print (ndo, bp, len - 20, len - 20, NULL, NULL);

}
