/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_atsvc.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_atsvc_init(TALLOC_CTX *);

/* atsvc - dcerpc server boilerplate generated by pidl */


static NTSTATUS atsvc__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_ATSVC_BIND
	return DCESRV_INTERFACE_ATSVC_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void atsvc__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_ATSVC_UNBIND
	DCESRV_INTERFACE_ATSVC_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS atsvc__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_atsvc.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_atsvc.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_atsvc.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_atsvc.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_atsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS atsvc__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct atsvc_JobAdd *r2 = (struct atsvc_JobAdd *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobAdd, NDR_IN, r2);
		}
		r2->out.result = dcesrv_atsvc_JobAdd(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobAdd will reply async\n"));
		}
		break;
	}
	case 1: {
		struct atsvc_JobDel *r2 = (struct atsvc_JobDel *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobDel, NDR_IN, r2);
		}
		r2->out.result = dcesrv_atsvc_JobDel(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobDel will reply async\n"));
		}
		break;
	}
	case 2: {
		struct atsvc_JobEnum *r2 = (struct atsvc_JobEnum *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobEnum, NDR_IN, r2);
		}
		r2->out.result = dcesrv_atsvc_JobEnum(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobEnum will reply async\n"));
		}
		break;
	}
	case 3: {
		struct atsvc_JobGetInfo *r2 = (struct atsvc_JobGetInfo *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobGetInfo, NDR_IN, r2);
		}
		r2->out.result = dcesrv_atsvc_JobGetInfo(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobGetInfo will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_atsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS atsvc__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct atsvc_JobAdd *r2 = (struct atsvc_JobAdd *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobAdd replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobAdd, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in atsvc_JobAdd\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 1: {
		struct atsvc_JobDel *r2 = (struct atsvc_JobDel *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobDel replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobDel, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in atsvc_JobDel\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 2: {
		struct atsvc_JobEnum *r2 = (struct atsvc_JobEnum *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobEnum replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobEnum, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in atsvc_JobEnum\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 3: {
		struct atsvc_JobGetInfo *r2 = (struct atsvc_JobGetInfo *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function atsvc_JobGetInfo replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(atsvc_JobGetInfo, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in atsvc_JobGetInfo\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_atsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS atsvc__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_atsvc.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_atsvc_interface = {
	.name		    = "atsvc",
	.syntax_id          = {{0x1ff70682,0x0a51,0x30e8,{0x07,0x6d},{0x74,0x0b,0xe8,0xce,0xe9,0x8b}},1.0},
	.bind		    = atsvc__op_bind,
	.unbind		    = atsvc__op_unbind,
	.ndr_pull	    = atsvc__op_ndr_pull,
	.dispatch	    = atsvc__op_dispatch,
	.reply		    = atsvc__op_reply,
	.ndr_push	    = atsvc__op_ndr_push,
#ifdef DCESRV_INTERFACE_ATSVC_FLAGS
	.flags              = DCESRV_INTERFACE_ATSVC_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS atsvc__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_atsvc.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_atsvc.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_atsvc_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("atsvc_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool atsvc__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_atsvc_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_atsvc_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_atsvc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool atsvc__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_atsvc_interface.name, name)==0) {
		memcpy(iface, &dcesrv_atsvc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_atsvc_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "atsvc",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_ATSVC_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_ATSVC_INIT_SERVER,
#else
	    .init_server = atsvc__op_init_server,
#endif
	    .interface_by_uuid = atsvc__op_interface_by_uuid,
	    .interface_by_name = atsvc__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'atsvc' endpoint server!\n"));
		return ret;
	}

	return ret;
}

