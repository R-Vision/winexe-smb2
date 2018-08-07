/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_remact.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_IRemoteActivation_init(TALLOC_CTX *);

/* IRemoteActivation - dcerpc server boilerplate generated by pidl */


static NTSTATUS IRemoteActivation__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_IREMOTEACTIVATION_BIND
	return DCESRV_INTERFACE_IREMOTEACTIVATION_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void IRemoteActivation__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_IREMOTEACTIVATION_UNBIND
	DCESRV_INTERFACE_IREMOTEACTIVATION_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS IRemoteActivation__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_IRemoteActivation.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_IRemoteActivation.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_IRemoteActivation.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_IRemoteActivation.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_IRemoteActivation, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS IRemoteActivation__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct RemoteActivation *r2 = (struct RemoteActivation *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(RemoteActivation, NDR_IN, r2);
		}
		r2->out.result = dcesrv_RemoteActivation(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function RemoteActivation will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_IRemoteActivation, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS IRemoteActivation__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct RemoteActivation *r2 = (struct RemoteActivation *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function RemoteActivation replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(RemoteActivation, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in RemoteActivation\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_IRemoteActivation, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS IRemoteActivation__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_IRemoteActivation.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_IRemoteActivation_interface = {
	.name		    = "IRemoteActivation",
	.syntax_id          = {{0x4d9f4ab8,0x7d1c,0x11cf,{0x86,0x1e},{0x00,0x20,0xaf,0x6e,0x7c,0x57}},0.0},
	.bind		    = IRemoteActivation__op_bind,
	.unbind		    = IRemoteActivation__op_unbind,
	.ndr_pull	    = IRemoteActivation__op_ndr_pull,
	.dispatch	    = IRemoteActivation__op_dispatch,
	.reply		    = IRemoteActivation__op_reply,
	.ndr_push	    = IRemoteActivation__op_ndr_push,
#ifdef DCESRV_INTERFACE_IREMOTEACTIVATION_FLAGS
	.flags              = DCESRV_INTERFACE_IREMOTEACTIVATION_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS IRemoteActivation__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_IRemoteActivation.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_IRemoteActivation.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_IRemoteActivation_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("IRemoteActivation_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool IRemoteActivation__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_IRemoteActivation_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_IRemoteActivation_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_IRemoteActivation_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool IRemoteActivation__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_IRemoteActivation_interface.name, name)==0) {
		memcpy(iface, &dcesrv_IRemoteActivation_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_IRemoteActivation_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "IRemoteActivation",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_IREMOTEACTIVATION_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_IREMOTEACTIVATION_INIT_SERVER,
#else
	    .init_server = IRemoteActivation__op_init_server,
#endif
	    .interface_by_uuid = IRemoteActivation__op_interface_by_uuid,
	    .interface_by_name = IRemoteActivation__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'IRemoteActivation' endpoint server!\n"));
		return ret;
	}

	return ret;
}

