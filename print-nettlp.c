/*
 * NetTLP printer
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

#include "tlp.h"

struct nettlp_hdr {
	uint16_t seq;
	uint32_t tstamp;
} __attribute__((packed));

static const struct tok tlp_flags[] = {
	{ TLP_FLAG_DIGEST_MASK, "T" },
	{ TLP_FLAG_EP_MASK, "E" },
	{ 0, NULL }
};

static const struct tok tlp_attrs[] = {
	{ TLP_ATTR_RELAX_MASK, "R" },
	{ TLP_ATTR_NOSNP_MASK, "N" },
	{ 0, NULL }
};

void nettlp_print_mr(netdissect_options *ndo, const struct tlp_mr_hdr *tlpm,
	u_int length)
{
	uint32_t *a;
	uint64_t addr;

	if (length < sizeof(struct tlp_mr_hdr))
		goto trunc;

	ND_PRINT("requester %02x:%02x, ", tlp_id_to_bus(tlpm->requester),
		 tlp_id_to_device(tlpm->requester));
	ND_PRINT("tag 0x%02x, ", tlpm->tag);
	ND_PRINT("last 0x%0x, first 0x%0x, ", tlpm->lstdw, tlpm->fstdw);

	a = (uint32_t *)(tlpm + 1);
	addr = ntohl(*a);
	if (tlp_is_3dw(tlpm->tlp.fmt_type)) {
		ND_PRINT("Addr 0x%08llx", addr);
	} else if (tlp_is_4dw(tlpm->tlp.fmt_type)) {
		a++;
		addr = (addr << 32) | ntohl(*a);
		ND_PRINT("Addr 0x%016llx", addr);
	}

	return;

trunc:
	nd_print_trunc(ndo);
}

void nettlp_print_cpl(netdissect_options *ndo, const struct tlp_cpl_hdr *tlpc,
	u_int length)
{
	if (length < sizeof(struct tlp_cpl_hdr))
		goto trunc;

	ND_PRINT("completer %02x:%02x, ", tlp_id_to_bus(tlpc->completer),
		 tlp_id_to_device(tlpc->completer));
	if (tlp_cpl_status(tlpc->stcnt) == TLP_CPL_STATUS_SC)
		ND_PRINT("success, ");
	else if (tlp_cpl_status(tlpc->stcnt) == TLP_CPL_STATUS_UR)
		ND_PRINT("unsupported request, ");
	else if (tlp_cpl_status(tlpc->stcnt) == TLP_CPL_STATUS_CRS)
		ND_PRINT("config request retry, ");
	else if (tlp_cpl_status(tlpc->stcnt) == TLP_CPL_STATUS_CA)
		ND_PRINT("completer abort, ");

	ND_PRINT("bc %d, ", tlp_cpl_bcnt(tlpc->stcnt));
	ND_PRINT("requester %02x:%02x, ", tlp_id_to_bus(tlpc->requester),
		 tlp_id_to_device(tlpc->requester));
	ND_PRINT("tag 0x%02x, ", tlpc->tag);
	ND_PRINT("lowaddr 0x%02x", tlpc->lowaddr);

	return;
trunc:
	nd_print_trunc(ndo);
}

void
nettlp_print_tlp(netdissect_options *ndo, const struct tlp_hdr *tlp,
		 u_int length)
{

	if (tlp_is_mrd(tlp->fmt_type))
		ND_PRINT("MRd, ");
	else if (tlp_is_mwr(tlp->fmt_type))
		ND_PRINT("MWr, ");
	else if (tlp_is_cpl(tlp->fmt_type) && tlp_is_wo_data(tlp->fmt_type))
		ND_PRINT("Cpl, ");
	else if (tlp_is_cpl(tlp->fmt_type) && tlp_is_w_data(tlp->fmt_type))
		ND_PRINT("CplD, ");
	else {
		ND_PRINT("Not Impled Fmt:Type 0x%x", tlp->fmt_type);
		return;
	}
	     
	if (ndo->ndo_vflag) {

		if (tlp_is_3dw(tlp->fmt_type))
			ND_PRINT("3DW, ");
		else if (tlp_is_4dw(tlp->fmt_type))
			ND_PRINT("4DW, ");
		else {
			ND_PRINT("Invalid DW 0x%x", tlp->fmt_type); 
			return;
		}

		if (tlp_is_w_data(tlp->fmt_type))
			ND_PRINT("WD, ");

		ND_PRINT("tc %x, ", tlp_tclass(tlp->tclass));
		ND_PRINT("flags [%s], ",
			 bittok2str_nosep(tlp_flags, "none",
					  tlp_flag(tlp->falen)));
		ND_PRINT("attrs [%s], ",
			 bittok2str_nosep(tlp_attrs, "none",
					  tlp_attr(tlp->falen)));
	}

	ND_PRINT("len %d, ", tlp_length(tlp->falen));

	if (tlp_is_mrd(tlp->fmt_type) || tlp_is_mwr(tlp->fmt_type))
		nettlp_print_mr(ndo, (const struct tlp_mr_hdr *)tlp, length);
	else if (tlp_is_cpl(tlp->fmt_type))
		nettlp_print_cpl(ndo, (const struct tlp_cpl_hdr *)tlp, length);
				 
	return;
}


/*
 * print a nettlp diagram
 */
void
nettlp_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	const struct nettlp_hdr *ntlp;

	ndo->ndo_protocol = "nettlp";
	if (length < sizeof(struct nettlp_hdr) + sizeof(struct tlp_hdr))
		goto trunc;

	ND_PRINT("NetTLP: ");

	ntlp = (const struct nettlp_hdr *)bp;

	if (ndo->ndo_vflag)
		ND_PRINT("seq 0x%04x, tstamp %u, ",
			 ntohs(ntlp->seq), ntohl(ntlp->tstamp));

	length -= sizeof(struct nettlp_hdr);
	nettlp_print_tlp(ndo, (const struct tlp_hdr *)(ntlp + 1), length);

	return;

trunc:
	nd_print_trunc(ndo);
}
