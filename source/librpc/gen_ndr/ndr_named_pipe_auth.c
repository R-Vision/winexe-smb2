/* parser auto-generated by pidl */

#include "includes.h"
#include "bin/default/librpc/gen_ndr/ndr_named_pipe_auth.h"

#include "librpc/gen_ndr/ndr_netlogon.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_auth.h"
static enum ndr_err_code ndr_push_named_pipe_auth_req_info4(struct ndr_push *ndr, int ndr_flags, const struct named_pipe_auth_req_info4 *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->remote_client_name));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->remote_client_addr));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->remote_client_port));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->local_server_name));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->local_server_addr));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->local_server_port));
		NDR_CHECK(ndr_push_unique_ptr(ndr, r->session_info));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->remote_client_name) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->remote_client_name, CH_UTF8)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->remote_client_name, CH_UTF8)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->remote_client_name, ndr_charset_length(r->remote_client_name, CH_UTF8), sizeof(uint8_t), CH_UTF8));
		}
		if (r->remote_client_addr) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->remote_client_addr, CH_DOS)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->remote_client_addr, CH_DOS)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->remote_client_addr, ndr_charset_length(r->remote_client_addr, CH_DOS), sizeof(uint8_t), CH_DOS));
		}
		if (r->local_server_name) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->local_server_name, CH_UTF8)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->local_server_name, CH_UTF8)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->local_server_name, ndr_charset_length(r->local_server_name, CH_UTF8), sizeof(uint8_t), CH_UTF8));
		}
		if (r->local_server_addr) {
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->local_server_addr, CH_DOS)));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, 0));
			NDR_CHECK(ndr_push_uint3264(ndr, NDR_SCALARS, ndr_charset_length(r->local_server_addr, CH_DOS)));
			NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, r->local_server_addr, ndr_charset_length(r->local_server_addr, CH_DOS), sizeof(uint8_t), CH_DOS));
		}
		if (r->session_info) {
			NDR_CHECK(ndr_push_auth_session_info_transport(ndr, NDR_SCALARS|NDR_BUFFERS, r->session_info));
		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_named_pipe_auth_req_info4(struct ndr_pull *ndr, int ndr_flags, struct named_pipe_auth_req_info4 *r)
{
	uint32_t _ptr_remote_client_name;
	uint32_t size_remote_client_name_1 = 0;
	uint32_t length_remote_client_name_1 = 0;
	TALLOC_CTX *_mem_save_remote_client_name_0 = NULL;
	uint32_t _ptr_remote_client_addr;
	uint32_t size_remote_client_addr_1 = 0;
	uint32_t length_remote_client_addr_1 = 0;
	TALLOC_CTX *_mem_save_remote_client_addr_0 = NULL;
	uint32_t _ptr_local_server_name;
	uint32_t size_local_server_name_1 = 0;
	uint32_t length_local_server_name_1 = 0;
	TALLOC_CTX *_mem_save_local_server_name_0 = NULL;
	uint32_t _ptr_local_server_addr;
	uint32_t size_local_server_addr_1 = 0;
	uint32_t length_local_server_addr_1 = 0;
	TALLOC_CTX *_mem_save_local_server_addr_0 = NULL;
	uint32_t _ptr_session_info;
	TALLOC_CTX *_mem_save_session_info_0 = NULL;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_remote_client_name));
		if (_ptr_remote_client_name) {
			NDR_PULL_ALLOC(ndr, r->remote_client_name);
		} else {
			r->remote_client_name = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_remote_client_addr));
		if (_ptr_remote_client_addr) {
			NDR_PULL_ALLOC(ndr, r->remote_client_addr);
		} else {
			r->remote_client_addr = NULL;
		}
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->remote_client_port));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_local_server_name));
		if (_ptr_local_server_name) {
			NDR_PULL_ALLOC(ndr, r->local_server_name);
		} else {
			r->local_server_name = NULL;
		}
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_local_server_addr));
		if (_ptr_local_server_addr) {
			NDR_PULL_ALLOC(ndr, r->local_server_addr);
		} else {
			r->local_server_addr = NULL;
		}
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->local_server_port));
		NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_session_info));
		if (_ptr_session_info) {
			NDR_PULL_ALLOC(ndr, r->session_info);
		} else {
			r->session_info = NULL;
		}
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		if (r->remote_client_name) {
			_mem_save_remote_client_name_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->remote_client_name, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->remote_client_name));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->remote_client_name));
			size_remote_client_name_1 = ndr_get_array_size(ndr, &r->remote_client_name);
			length_remote_client_name_1 = ndr_get_array_length(ndr, &r->remote_client_name);
			if (length_remote_client_name_1 > size_remote_client_name_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_remote_client_name_1, length_remote_client_name_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_remote_client_name_1, sizeof(uint8_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->remote_client_name, length_remote_client_name_1, sizeof(uint8_t), CH_UTF8));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_remote_client_name_0, 0);
		}
		if (r->remote_client_addr) {
			_mem_save_remote_client_addr_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->remote_client_addr, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->remote_client_addr));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->remote_client_addr));
			size_remote_client_addr_1 = ndr_get_array_size(ndr, &r->remote_client_addr);
			length_remote_client_addr_1 = ndr_get_array_length(ndr, &r->remote_client_addr);
			if (length_remote_client_addr_1 > size_remote_client_addr_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_remote_client_addr_1, length_remote_client_addr_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_remote_client_addr_1, sizeof(uint8_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->remote_client_addr, length_remote_client_addr_1, sizeof(uint8_t), CH_DOS));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_remote_client_addr_0, 0);
		}
		if (r->local_server_name) {
			_mem_save_local_server_name_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->local_server_name, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->local_server_name));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->local_server_name));
			size_local_server_name_1 = ndr_get_array_size(ndr, &r->local_server_name);
			length_local_server_name_1 = ndr_get_array_length(ndr, &r->local_server_name);
			if (length_local_server_name_1 > size_local_server_name_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_local_server_name_1, length_local_server_name_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_local_server_name_1, sizeof(uint8_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->local_server_name, length_local_server_name_1, sizeof(uint8_t), CH_UTF8));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_local_server_name_0, 0);
		}
		if (r->local_server_addr) {
			_mem_save_local_server_addr_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->local_server_addr, 0);
			NDR_CHECK(ndr_pull_array_size(ndr, &r->local_server_addr));
			NDR_CHECK(ndr_pull_array_length(ndr, &r->local_server_addr));
			size_local_server_addr_1 = ndr_get_array_size(ndr, &r->local_server_addr);
			length_local_server_addr_1 = ndr_get_array_length(ndr, &r->local_server_addr);
			if (length_local_server_addr_1 > size_local_server_addr_1) {
				return ndr_pull_error(ndr, NDR_ERR_ARRAY_SIZE, "Bad array size %u should exceed array length %u", size_local_server_addr_1, length_local_server_addr_1);
			}
			NDR_CHECK(ndr_check_string_terminator(ndr, length_local_server_addr_1, sizeof(uint8_t)));
			NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->local_server_addr, length_local_server_addr_1, sizeof(uint8_t), CH_DOS));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_local_server_addr_0, 0);
		}
		if (r->session_info) {
			_mem_save_session_info_0 = NDR_PULL_GET_MEM_CTX(ndr);
			NDR_PULL_SET_MEM_CTX(ndr, r->session_info, 0);
			NDR_CHECK(ndr_pull_auth_session_info_transport(ndr, NDR_SCALARS|NDR_BUFFERS, r->session_info));
			NDR_PULL_SET_MEM_CTX(ndr, _mem_save_session_info_0, 0);
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_req_info4(struct ndr_print *ndr, const char *name, const struct named_pipe_auth_req_info4 *r)
{
	ndr_print_struct(ndr, name, "named_pipe_auth_req_info4");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_ptr(ndr, "remote_client_name", r->remote_client_name);
	ndr->depth++;
	if (r->remote_client_name) {
		ndr_print_string(ndr, "remote_client_name", r->remote_client_name);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "remote_client_addr", r->remote_client_addr);
	ndr->depth++;
	if (r->remote_client_addr) {
		ndr_print_string(ndr, "remote_client_addr", r->remote_client_addr);
	}
	ndr->depth--;
	ndr_print_uint16(ndr, "remote_client_port", r->remote_client_port);
	ndr_print_ptr(ndr, "local_server_name", r->local_server_name);
	ndr->depth++;
	if (r->local_server_name) {
		ndr_print_string(ndr, "local_server_name", r->local_server_name);
	}
	ndr->depth--;
	ndr_print_ptr(ndr, "local_server_addr", r->local_server_addr);
	ndr->depth++;
	if (r->local_server_addr) {
		ndr_print_string(ndr, "local_server_addr", r->local_server_addr);
	}
	ndr->depth--;
	ndr_print_uint16(ndr, "local_server_port", r->local_server_port);
	ndr_print_ptr(ndr, "session_info", r->session_info);
	ndr->depth++;
	if (r->session_info) {
		ndr_print_auth_session_info_transport(ndr, "session_info", r->session_info);
	}
	ndr->depth--;
	ndr->depth--;
}

static enum ndr_err_code ndr_push_named_pipe_auth_req_info(struct ndr_push *ndr, int ndr_flags, const union named_pipe_auth_req_info *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		NDR_CHECK(ndr_push_union_align(ndr, 5));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, level));
		NDR_CHECK(ndr_push_union_align(ndr, 5));
		switch (level) {
			case 4: {
				NDR_CHECK(ndr_push_named_pipe_auth_req_info4(ndr, NDR_SCALARS, &r->info4));
			break; }

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		switch (level) {
			case 4:
				NDR_CHECK(ndr_push_named_pipe_auth_req_info4(ndr, NDR_BUFFERS, &r->info4));
			break;

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_named_pipe_auth_req_info(struct ndr_pull *ndr, int ndr_flags, union named_pipe_auth_req_info *r)
{
	uint32_t level;
	uint32_t _level;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		level = ndr_pull_get_switch_value(ndr, r);
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_level));
		if (_level != level) {
			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u for r at %s", _level, __location__);
		}
		NDR_CHECK(ndr_pull_union_align(ndr, 5));
		switch (level) {
			case 4: {
				NDR_CHECK(ndr_pull_named_pipe_auth_req_info4(ndr, NDR_SCALARS, &r->info4));
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		/* The token is not needed after this. */
		level = ndr_pull_steal_switch_value(ndr, r);
		switch (level) {
			case 4:
				NDR_CHECK(ndr_pull_named_pipe_auth_req_info4(ndr, NDR_BUFFERS, &r->info4));
			break;

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_req_info(struct ndr_print *ndr, const char *name, const union named_pipe_auth_req_info *r)
{
	uint32_t level;
	level = ndr_print_get_switch_value(ndr, r);
	ndr_print_union(ndr, name, level, "named_pipe_auth_req_info");
	switch (level) {
		case 4:
			ndr_print_named_pipe_auth_req_info4(ndr, "info4", &r->info4);
		break;

		default:
			ndr_print_bad_level(ndr, name, level);
	}
}

_PUBLIC_ enum ndr_err_code ndr_push_named_pipe_auth_req(struct ndr_push *ndr, int ndr_flags, const struct named_pipe_auth_req *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 5));
		{
			uint32_t _flags_save_uint32 = ndr->flags;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_size_named_pipe_auth_req(r, ndr->flags) - 4));
			ndr->flags = _flags_save_uint32;
		}
		NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, NAMED_PIPE_AUTH_MAGIC, 4, sizeof(uint8_t), CH_DOS));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->level));
		NDR_CHECK(ndr_push_set_switch_value(ndr, &r->info, r->level));
		NDR_CHECK(ndr_push_named_pipe_auth_req_info(ndr, NDR_SCALARS, &r->info));
		NDR_CHECK(ndr_push_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_push_named_pipe_auth_req_info(ndr, NDR_BUFFERS, &r->info));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_named_pipe_auth_req(struct ndr_pull *ndr, int ndr_flags, struct named_pipe_auth_req *r)
{
	uint32_t size_magic_0 = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 5));
		{
			uint32_t _flags_save_uint32 = ndr->flags;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->length));
			ndr->flags = _flags_save_uint32;
		}
		size_magic_0 = 4;
		NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->magic, size_magic_0, sizeof(uint8_t), CH_DOS));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->level));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->info, r->level));
		NDR_CHECK(ndr_pull_named_pipe_auth_req_info(ndr, NDR_SCALARS, &r->info));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
	}
	if (ndr_flags & NDR_BUFFERS) {
		NDR_CHECK(ndr_pull_named_pipe_auth_req_info(ndr, NDR_BUFFERS, &r->info));
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_req(struct ndr_print *ndr, const char *name, const struct named_pipe_auth_req *r)
{
	ndr_print_struct(ndr, name, "named_pipe_auth_req");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	{
		uint32_t _flags_save_uint32 = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
		ndr_print_uint32(ndr, "length", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?ndr_size_named_pipe_auth_req(r, ndr->flags) - 4:r->length);
		ndr->flags = _flags_save_uint32;
	}
	ndr_print_string(ndr, "magic", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?NAMED_PIPE_AUTH_MAGIC:r->magic);
	ndr_print_uint32(ndr, "level", r->level);
	ndr_print_set_switch_value(ndr, &r->info, r->level);
	ndr_print_named_pipe_auth_req_info(ndr, "info", &r->info);
	ndr->depth--;
}

_PUBLIC_ size_t ndr_size_named_pipe_auth_req(const struct named_pipe_auth_req *r, int flags)
{
	return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_named_pipe_auth_req);
}

static enum ndr_err_code ndr_push_named_pipe_auth_rep_info4(struct ndr_push *ndr, int ndr_flags, const struct named_pipe_auth_rep_info4 *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 8));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->file_type));
		NDR_CHECK(ndr_push_uint16(ndr, NDR_SCALARS, r->device_state));
		NDR_CHECK(ndr_push_hyper(ndr, NDR_SCALARS, r->allocation_size));
		NDR_CHECK(ndr_push_trailer_align(ndr, 8));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_named_pipe_auth_rep_info4(struct ndr_pull *ndr, int ndr_flags, struct named_pipe_auth_rep_info4 *r)
{
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 8));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->file_type));
		NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->device_state));
		NDR_CHECK(ndr_pull_hyper(ndr, NDR_SCALARS, &r->allocation_size));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 8));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_rep_info4(struct ndr_print *ndr, const char *name, const struct named_pipe_auth_rep_info4 *r)
{
	ndr_print_struct(ndr, name, "named_pipe_auth_rep_info4");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	ndr_print_uint16(ndr, "file_type", r->file_type);
	ndr_print_uint16(ndr, "device_state", r->device_state);
	ndr_print_hyper(ndr, "allocation_size", r->allocation_size);
	ndr->depth--;
}

static enum ndr_err_code ndr_push_named_pipe_auth_rep_info(struct ndr_push *ndr, int ndr_flags, const union named_pipe_auth_rep_info *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		NDR_CHECK(ndr_push_union_align(ndr, 8));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, level));
		NDR_CHECK(ndr_push_union_align(ndr, 8));
		switch (level) {
			case 4: {
				NDR_CHECK(ndr_push_named_pipe_auth_rep_info4(ndr, NDR_SCALARS, &r->info4));
			break; }

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		uint32_t level = ndr_push_get_switch_value(ndr, r);
		switch (level) {
			case 4:
			break;

			default:
				return ndr_push_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

static enum ndr_err_code ndr_pull_named_pipe_auth_rep_info(struct ndr_pull *ndr, int ndr_flags, union named_pipe_auth_rep_info *r)
{
	uint32_t level;
	uint32_t _level;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		level = ndr_pull_get_switch_value(ndr, r);
		NDR_CHECK(ndr_pull_union_align(ndr, 8));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &_level));
		if (_level != level) {
			return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u for r at %s", _level, __location__);
		}
		NDR_CHECK(ndr_pull_union_align(ndr, 8));
		switch (level) {
			case 4: {
				NDR_CHECK(ndr_pull_named_pipe_auth_rep_info4(ndr, NDR_SCALARS, &r->info4));
			break; }

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	if (ndr_flags & NDR_BUFFERS) {
		/* The token is not needed after this. */
		level = ndr_pull_steal_switch_value(ndr, r);
		switch (level) {
			case 4:
			break;

			default:
				return ndr_pull_error(ndr, NDR_ERR_BAD_SWITCH, "Bad switch value %u at %s", level, __location__);
		}
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_rep_info(struct ndr_print *ndr, const char *name, const union named_pipe_auth_rep_info *r)
{
	uint32_t level;
	level = ndr_print_get_switch_value(ndr, r);
	ndr_print_union(ndr, name, level, "named_pipe_auth_rep_info");
	switch (level) {
		case 4:
			ndr_print_named_pipe_auth_rep_info4(ndr, "info4", &r->info4);
		break;

		default:
			ndr_print_bad_level(ndr, name, level);
	}
}

_PUBLIC_ enum ndr_err_code ndr_push_named_pipe_auth_rep(struct ndr_push *ndr, int ndr_flags, const struct named_pipe_auth_rep *r)
{
	NDR_PUSH_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_push_align(ndr, 8));
		{
			uint32_t _flags_save_uint32 = ndr->flags;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
			NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, ndr_size_named_pipe_auth_rep(r, ndr->flags) - 4));
			ndr->flags = _flags_save_uint32;
		}
		NDR_CHECK(ndr_push_charset(ndr, NDR_SCALARS, NAMED_PIPE_AUTH_MAGIC, 4, sizeof(uint8_t), CH_DOS));
		NDR_CHECK(ndr_push_uint32(ndr, NDR_SCALARS, r->level));
		NDR_CHECK(ndr_push_set_switch_value(ndr, &r->info, r->level));
		NDR_CHECK(ndr_push_named_pipe_auth_rep_info(ndr, NDR_SCALARS, &r->info));
		NDR_CHECK(ndr_push_NTSTATUS(ndr, NDR_SCALARS, r->status));
		NDR_CHECK(ndr_push_trailer_align(ndr, 8));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ enum ndr_err_code ndr_pull_named_pipe_auth_rep(struct ndr_pull *ndr, int ndr_flags, struct named_pipe_auth_rep *r)
{
	uint32_t size_magic_0 = 0;
	NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
	if (ndr_flags & NDR_SCALARS) {
		NDR_CHECK(ndr_pull_align(ndr, 8));
		{
			uint32_t _flags_save_uint32 = ndr->flags;
			ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
			NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->length));
			ndr->flags = _flags_save_uint32;
		}
		size_magic_0 = 4;
		NDR_CHECK(ndr_pull_charset(ndr, NDR_SCALARS, &r->magic, size_magic_0, sizeof(uint8_t), CH_DOS));
		NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->level));
		NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->info, r->level));
		NDR_CHECK(ndr_pull_named_pipe_auth_rep_info(ndr, NDR_SCALARS, &r->info));
		NDR_CHECK(ndr_pull_NTSTATUS(ndr, NDR_SCALARS, &r->status));
		NDR_CHECK(ndr_pull_trailer_align(ndr, 8));
	}
	if (ndr_flags & NDR_BUFFERS) {
	}
	return NDR_ERR_SUCCESS;
}

_PUBLIC_ void ndr_print_named_pipe_auth_rep(struct ndr_print *ndr, const char *name, const struct named_pipe_auth_rep *r)
{
	ndr_print_struct(ndr, name, "named_pipe_auth_rep");
	if (r == NULL) { ndr_print_null(ndr); return; }
	ndr->depth++;
	{
		uint32_t _flags_save_uint32 = ndr->flags;
		ndr_set_flags(&ndr->flags, LIBNDR_FLAG_BIGENDIAN);
		ndr_print_uint32(ndr, "length", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?ndr_size_named_pipe_auth_rep(r, ndr->flags) - 4:r->length);
		ndr->flags = _flags_save_uint32;
	}
	ndr_print_string(ndr, "magic", (ndr->flags & LIBNDR_PRINT_SET_VALUES)?NAMED_PIPE_AUTH_MAGIC:r->magic);
	ndr_print_uint32(ndr, "level", r->level);
	ndr_print_set_switch_value(ndr, &r->info, r->level);
	ndr_print_named_pipe_auth_rep_info(ndr, "info", &r->info);
	ndr_print_NTSTATUS(ndr, "status", r->status);
	ndr->depth--;
}

_PUBLIC_ size_t ndr_size_named_pipe_auth_rep(const struct named_pipe_auth_rep *r, int flags)
{
	return ndr_size_struct(r, flags, (ndr_push_flags_fn_t)ndr_push_named_pipe_auth_rep);
}

