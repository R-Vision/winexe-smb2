/* parser auto-generated by pidl */

#include "includes.h"
#include "bin/default/librpc/gen_ndr/ndr_file_id.h"

_PUBLIC_ enum ndr_err_code ndr_push_file_id(struct ndr_push *ndr, int ndr_flags, const struct file_id *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 4));
		NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->devid));
		NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->inode));
		NDR_CHECK(ndr_push_udlong(ndr, NDR_SCALARS, r->extid));
		NDR_CHECK(ndr_push_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_file_id(struct ndr_pull *ndr, int ndr_flags, struct file_id *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 4));
		NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->devid));
		NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->inode));
		NDR_CHECK(ndr_pull_udlong(ndr, NDR_SCALARS, &r->extid));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_file_id(struct ndr_print *ndr, const char *name, const struct file_id *r)
{
	ndr_print_struct(ndr, name, "file_id");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_udlong(ndr, "devid", r->devid);
	ndr_print_udlong(ndr, "inode", r->inode);
	ndr_print_udlong(ndr, "extid", r->extid);
	ndr->depth--;
}
