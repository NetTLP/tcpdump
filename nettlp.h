/*
 * nettlp.h
 */

#ifndef nettlp_h
#define nettlp_h

#include <endian.h>

struct nettlp_hdr {
	uint16_t	seq;
	uint32_t	tstamp;
} __attribute__((packed));

/* 
 * = Common Header
 * 
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 */

struct tlp_hdr {
	uint8_t		fmt_type;	/* Formant and Type */
	uint8_t		tclass;		/* Traffic Class */
	uint16_t	flag_len;	/* Flags, Attrs, and Length */

} __attribute__((packed));

/* TLP Format */
#define TLP_FMT_DW_MASK		0x20
#define TLP_FMT_3DW		0x00
#define TLP_FMT_4DW		0x20

#define tlp_fmt_dw(ft) ((ft) & TLP_FMT_DW_MASK)
#define tlp_is_3dw(ft) (tlp_fmt_dw(ft) == TLP_FMT_3DW)
#define tlp_is_4dw(ft) (tlp_fmt_dw(ft) == TLP_FMT_4DW)

#define TLP_FMT_DATA_MASK	0x40
#define TLP_FMT_WO_DATA		0x00
#define TLP_FMT_W_DATA		0x40

#define tlp_fmt_data(ft) ((ft) & TLP_FMT_DATA_MASK)
#define tlp_is_wo_data(ft) (tlp_fmt_data(ft) == TLP_FMT_WO_DATA)
#define tlp_is_w_data(ft) (tlp_fmt_data(ft) == TLP_FMT_W_DATA)

#define tlp_set_fmt(ft, dw, wd) \
		(ft) |= ((dw) & TLP_FMT_DW_MASK) |	\
			((wd) & TLP_FMT_DATA_MASK)


/* TLP Type */
#define TLP_TYPE_MASK		0x1F
#define TLP_TYPE_MRd		0x00
#define TLP_TYPE_MRdLk		0x01
#define TLP_TYPE_MWr		0x00
#define TLP_TYPE_Cpl		0x0A

#define tlp_type(ft) ((ft) & TLP_TYPE_MASK)
#define tlp_is_mrd(ft) (tlp_type(ft) == TLP_TYPE_MRd && tlp_is_wo_data(ft))
#define tlp_is_mwr(ft) (tlp_type(ft) == TLP_TYPE_MWr && tlp_is_w_data(ft))
#define tlp_is_cpl(ft) (tlp_type(ft) == TLP_TYPE_Cpl)
#define tlp_set_type(ft, v) ft = ((ft & ~TLP_TYPE_MASK) | (v & TLP_TYPE_MASK))


/* Traffic class */
#define TLP_TCLASS_MASK		0x70
#define tlp_tclass(tc) ((tc & TLP_TCLASS_MASK) >> 4)
#define tlp_set_tclass(tc, v) (tc) = (((v) << 4) & TLP_TCLASS_MASK)
		

/* TLP Flags */
#define TLP_FLAG_MASK		0xC000
#define tlp_flag(fl) ((ntohs(fl) & TLP_FLAG_MASK) >> 14)

#define TLP_FLAG_DIGEST_MASK	0x2
#define tlp_flag_digest(fl) (tlp_flag(fl) & TLP_FLAG_DIGEST_MASK)
#define tlp_flag_set_digest(fl) \
	fl = htons((ntohs(fl) | (TLP_FLAG_DIGEST_MASK << 14)))
#define tlp_flag_unset_digest(fl) \
	fl = htons((ntohs(fl) | (TLP_FLAG_DIGEST_MASK << 14)))

#define TLP_FLAG_EP_MASK	0x1
#define tlp_flag_ep(fl) (tlp_flag(fl) & TLP_FLAG_EP_MASK)
#define tlp_flag_set_ep(fl) \
	fl = htons((ntohs(fl) | (TLP_FLAG_EP_MASK << 14)))
#define tlp_flag_unset_ep(fl) \
	fl = htons((ntohs(fl) | (TLP_FLAG_EP_MASK << 14)))


/* TLP Attrs */
#define TLP_ATTR_MASK		0x3000
#define tlp_attr(fl) ((ntohs(fl) & TLP_ATTR_MASK) >> 14)

#define TLP_ATTR_RELAX_MASK	0x2
#define tlp_attr_relax(fl) (tlp_attr(fl) & TLP_ATTR_RELAX_MASK)
#define tlp_attr_set_relax(fl) \
	fl = htons((ntohs(fl) | (TLP_ATTR_RELAX_MASK << 14)))
#define tlp_attr_unset_relax(fl) \
	fl = htons((ntohs(fl) | (TLP_ATTR_RELAX_MASK << 14)))

#define TLP_ATTR_NOSNP_MASK	0x1
#define tlp_attr_nosnp(fl) (tlp_attr(fl) & TLP_ATTR_NOSNP_MASK)
#define tlp_attr_set_nosnp(fl) \
	fl = htons((ntohs(fl) | (TLP_ATTR_NOSNP_MASK << 14)))
#define tlp_attr_unset_nosnp(fl) \
	fl = htons((ntohs(fl) | (TLP_ATTR_NOSNP_MASK << 14)))

/* TLP Length */
#define TLP_LENGTH_MASK		0x03FF
#define tlp_len(fl) (ntohs(fl) & TLP_LENGTH_MASK)
#define tlp_set_len(fl, v) \
	fl = (fl & ~TLP_LENGTH_MASK) | (htons(fl) & TLP_LENGTH_MASK)



/*
 * = Memory Request Header
 *
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 * |         Requeseter ID         |      Tag      | LastDW| 1stDW |
 * +---------------+---------------+---------------+---------------+
 * |                          Address                          | R |
 * +---------------+---------------+---------------+---------------+
 * 
 * or, 64bit address (4DW header)
 * +---------------+---------------+---------------+---------------+
 * |                          Address                              |
 * +---------------+---------------+---------------+---------------+
 * |                          Address                          | R |
 * +---------------+---------------+---------------+---------------+
 */

struct tlp_mr_hdr {
	struct tlp_hdr tlp;

	uint16_t requester;
	uint8_t	tag;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t fstdw : 4;
	uint8_t lstdw : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t lstdw : 4;
	uint8_t fstdw : 4;
#else
# error "Please fix <bits/endian.h>"
#endif
	
} __attribute__((packed));


#define tlp_id_to_bus(id) (ntohs(id) >> 8)
#define tlp_id_to_device(id) (ntohs(id) & 0x00FF)


/*
 * = Completion Header
 *
 * +---------------+---------------+---------------+---------------+
 * |       0       |       1       |       2       |       3       |
 * +---------------+---------------+---------------+---------------+
 * |7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|7|6|5|4|3|2|1|0|
 * +---------------+---------------+---------------+---------------+
 * |R|Fmt|  Type   |R| TC  |   R   |T|E|Atr| R |      Length       |
 * +---------------+---------------+---------------+---------------+
 * |          Completer ID         |CmpSt|B|      Byte Count       |
 * +---------------+---------------+---------------+---------------+ 
 * |          Requester ID         |     Tag       |R| Lower Addr  |
 * +---------------+---------------+---------------+---------------+ 
 */

struct tlp_cpl_hdr {
	struct tlp_hdr tlp;

	uint16_t completer;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t status :4;	/* Completion status and BCM (not used) */
	uint16_t count :12;	/* Byte Count */
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t count :12;	/* Byte Count */
	uint8_t status :4;	/* Completion status and BCM (not used) */
#else
# error "Please fix <bits/endian.h>"
#endif
	uint16_t requester;
	uint8_t tag;
	uint8_t lowaddr;
} __attribute__((packed));

#define TLP_CPL_STATUS_MASK	0xE
#define tlp_cpl_status(st) ((st) & TLP_CPL_STATUS_MASK)

#define TLP_CPL_STATUS_SC	0x0	/* Successful Completion */
#define TLP_CPL_STATUS_UR	0x2	/* Unsupported Request */
#define TLP_CPL_STATUS_CRS	0x4	/* Configratuon Request Retry Status */
#define TLP_CPL_STATUS_CA	0x8	/* Completer Abort */


#endif	/* nettlp_h */
