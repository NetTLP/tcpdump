
/* dump simple QUIC common header for my experimental use */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include "interface.h"
#include "extract.h"


/*
 * QUIC header, draft-tsvwg-quic-protocol-00
 *              QUIC: A UDP-Based Secure and Reliable Transport for HTTP/2
 *
 *
 *     0        1        2        3        4            8
 * +--------+--------+--------+--------+--------+---    ---+
 * | Public |    Connection ID (0, 8, 32, or 64)    ...    | ->
 * |Flags(8)|      (variable length)                       |
 * +--------+--------+--------+--------+--------+---    ---+
 *
 *      9       10       11        12
 * +--------+--------+--------+--------+
 * |      Quic Version (32)            | ->
 * |         (optional)                |
 * +--------+--------+--------+--------+
 *
 *     13      14       15        16        17       18       19       20
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * |         Sequence Number (8, 16, 32, or 48)          |Private | FEC (8)|
 * |                         (variable length)           |Flags(8)|  (opt) |
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 */

/* Public Flags */
#define QUIC_PUB_FLAG_VERSION	0x01
#define QUIC_PUB_FLAG_RESET	0x02
#define QUIC_PUB_FLAG_1BYTE_CID	0x04
#define QUIC_PUB_FLAG_4BYTE_CID	0x08
#define QUIC_PUB_FLAG_8BYTE_CID	0x0c
#define QUIC_PUB_FLAG_2BYTE_SEQ	0x10
#define QUIC_PUB_FLAG_4BYTE_SEQ	0x20
#define QUIC_PUB_FLAG_6BYTE_SEQ	0x30

/* Private Flags */
#define QUIC_PRV_FLAG_ENTROPY	0x01
#define QUIC_PRV_FLAG_FECGROUP	0x02
#define QUIC_PRV_FLAG_FEC	0x04


#define NEXTLEN(len, next)						\
	do {								\
		if (len < next) {					\
			ND_PRINT ((ndo, "truncated-packet (-%d)",	\
				   next - len));			\
			return;						\
		}							\
		len -= next;						\
	} while (0)


static void quic_version_print(netdissect_options *ndo,
			       const u_char *bp, u_int len);
static void quic_public_reset_print (netdissect_options *ndo,
				     const u_char *bp, u_int len);
static void quic_frame_print(netdissect_options *ndo,
			     const u_char *bp, u_int len);


void
quic_print(netdissect_options *ndo, const u_char *bp, u_int len)
{
	uint8_t public_flags, private_flags, fec;
	uint32_t version;
	uint64_t cid, seq;
	
	/* XXX: check length */

	if (len < 1) {
		ND_PRINT ((ndo, "[|QUIC]"));
		return;
	}

	ND_PRINT((ndo, "QUIC, "));

	NEXTLEN (len, 1);
	public_flags = *bp;
	ND_PRINT((ndo, "public flags 0x%02x, ", public_flags));
	bp += 1;

	switch (public_flags & QUIC_PUB_FLAG_8BYTE_CID) {
	case 0 :
		break;

	case QUIC_PUB_FLAG_1BYTE_CID :
		NEXTLEN (len, 1);
		cid = *bp;
		ND_PRINT ((ndo, "cid[1b] 0x%x, ", cid));
		bp += 1;
		break;

	case QUIC_PUB_FLAG_4BYTE_CID :
		NEXTLEN (len, 4);
		cid = EXTRACT_32BITS(bp);
		ND_PRINT ((ndo, "cid[4b] 0x%x, ", cid));
		bp += 4;
		break;

	case QUIC_PUB_FLAG_8BYTE_CID :
		NEXTLEN (len, 8);
		cid = EXTRACT_64BITS(bp);
		ND_PRINT ((ndo, "cid[8b] 0x%x, ", cid));
		bp += 8;
		break;
	}

	if (public_flags & QUIC_PUB_FLAG_VERSION) {
		NEXTLEN (len, 4);
		version = EXTRACT_32BITS (bp);
		ND_PRINT ((ndo, "version 0x%x, ", version));
		bp += 4;
	}

	switch (public_flags & QUIC_PUB_FLAG_6BYTE_SEQ) {
	case 0 :
		NEXTLEN (len, 1);
		seq = *bp;
		ND_PRINT ((ndo, "seq[1b] %u, " , seq));
		bp += 1;
		break;

	case QUIC_PUB_FLAG_2BYTE_SEQ :
		NEXTLEN (len, 2);
		seq = EXTRACT_16BITS (bp);
		ND_PRINT ((ndo, "seq[2b] %u, ", seq));
		bp += 2;
		break;

	case QUIC_PUB_FLAG_4BYTE_SEQ :
		NEXTLEN (len, 4);
		seq = EXTRACT_32BITS (bp);
		ND_PRINT ((ndo, "seq[4b] %u, ", seq));
		bp += 4;
		break;

	case QUIC_PUB_FLAG_6BYTE_SEQ :
		NEXTLEN (len, 6);
		seq = EXTRACT_48BITS (bp);
		ND_PRINT ((ndo, "seq[6b] %u, ", seq));
		bp += 6;
		break;
	}

#if 0	/* XXX: ??? */
	NEXTLEN (len, 1);
	private_flags = *bp;
	ND_PRINT((ndo, "private flags 0x%02x, ", private_flags));
	bp += 1;

	if (private_flags & (QUIC_PRV_FLAG_FECGROUP | QUIC_PRV_FLAG_FEC)) {
		NEXTLEN (len, 1);
		fec = *bp;
		ND_PRINT((ndo, "fec 0x%02x, ", fec));
		bp += 1;
	}
#endif

	if (public_flags & QUIC_PUB_FLAG_VERSION)
		quic_version_print (ndo, bp, len);

	else if (public_flags & QUIC_PUB_FLAG_RESET)
		quic_public_reset_print (ndo, bp, len);

	else
		quic_frame_print (ndo, bp, len);
}


static void
quic_version_print (netdissect_options *ndo, const u_char *bp, u_int len)
{
	ND_PRINT ((ndo, "Version Negotiation"));
}

static void
quic_public_reset_print (netdissect_options *ndo, const u_char *bp, u_int len)
{
	ND_PRINT ((ndo, "Public Reset"));
}

static void
quic_frame_print (netdissect_options *ndo, const u_char *bp, u_int len)
{
	ND_PRINT ((ndo, "Frame"));
}
