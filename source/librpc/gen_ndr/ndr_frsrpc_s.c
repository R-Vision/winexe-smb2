/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_frsrpc.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_frsrpc_init(TALLOC_CTX *);

/* frsrpc - dcerpc server boilerplate generated by pidl */


static NTSTATUS frsrpc__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_FRSRPC_BIND
	return DCESRV_INTERFACE_FRSRPC_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void frsrpc__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_FRSRPC_UNBIND
	DCESRV_INTERFACE_FRSRPC_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS frsrpc__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_frsrpc.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_frsrpc.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_frsrpc.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_frsrpc.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_frsrpc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frsrpc__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct frsrpc_FrsSendCommPkt *r2 = (struct frsrpc_FrsSendCommPkt *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsSendCommPkt, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frsrpc_FrsSendCommPkt(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsSendCommPkt will reply async\n"));
		}
		break;
	}
	case 1: {
		struct frsrpc_FrsVerifyPromotionParent *r2 = (struct frsrpc_FrsVerifyPromotionParent *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsVerifyPromotionParent, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frsrpc_FrsVerifyPromotionParent(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsVerifyPromotionParent will reply async\n"));
		}
		break;
	}
	case 2: {
		struct frsrpc_FrsStartPromotionParent *r2 = (struct frsrpc_FrsStartPromotionParent *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsStartPromotionParent, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frsrpc_FrsStartPromotionParent(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsStartPromotionParent will reply async\n"));
		}
		break;
	}
	case 3: {
		struct frsrpc_FrsNOP *r2 = (struct frsrpc_FrsNOP *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsNOP, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frsrpc_FrsNOP(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsNOP will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_frsrpc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frsrpc__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct frsrpc_FrsSendCommPkt *r2 = (struct frsrpc_FrsSendCommPkt *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsSendCommPkt replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsSendCommPkt, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frsrpc_FrsSendCommPkt\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 1: {
		struct frsrpc_FrsVerifyPromotionParent *r2 = (struct frsrpc_FrsVerifyPromotionParent *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsVerifyPromotionParent replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsVerifyPromotionParent, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frsrpc_FrsVerifyPromotionParent\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 2: {
		struct frsrpc_FrsStartPromotionParent *r2 = (struct frsrpc_FrsStartPromotionParent *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsStartPromotionParent replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsStartPromotionParent, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frsrpc_FrsStartPromotionParent\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 3: {
		struct frsrpc_FrsNOP *r2 = (struct frsrpc_FrsNOP *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frsrpc_FrsNOP replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frsrpc_FrsNOP, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frsrpc_FrsNOP\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_frsrpc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frsrpc__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_frsrpc.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_frsrpc_interface = {
	.name		    = "frsrpc",
	.syntax_id          = {{0xf5cc59b4,0x4264,0x101a,{0x8c,0x59},{0x08,0x00,0x2b,0x2f,0x84,0x26}},65537},
	.bind		    = frsrpc__op_bind,
	.unbind		    = frsrpc__op_unbind,
	.ndr_pull	    = frsrpc__op_ndr_pull,
	.dispatch	    = frsrpc__op_dispatch,
	.reply		    = frsrpc__op_reply,
	.ndr_push	    = frsrpc__op_ndr_push,
#ifdef DCESRV_INTERFACE_FRSRPC_FLAGS
	.flags              = DCESRV_INTERFACE_FRSRPC_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS frsrpc__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_frsrpc.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_frsrpc.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_frsrpc_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("frsrpc_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool frsrpc__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_frsrpc_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_frsrpc_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_frsrpc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool frsrpc__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_frsrpc_interface.name, name)==0) {
		memcpy(iface, &dcesrv_frsrpc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_frsrpc_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "frsrpc",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_FRSRPC_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_FRSRPC_INIT_SERVER,
#else
	    .init_server = frsrpc__op_init_server,
#endif
	    .interface_by_uuid = frsrpc__op_interface_by_uuid,
	    .interface_by_name = frsrpc__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'frsrpc' endpoint server!\n"));
		return ret;
	}

	return ret;
}

