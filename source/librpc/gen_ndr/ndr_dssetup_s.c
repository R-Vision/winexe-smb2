/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_dssetup.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_dssetup_init(TALLOC_CTX *);

/* dssetup - dcerpc server boilerplate generated by pidl */


static NTSTATUS dssetup__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_DSSETUP_BIND
	return DCESRV_INTERFACE_DSSETUP_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void dssetup__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_DSSETUP_UNBIND
	DCESRV_INTERFACE_DSSETUP_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS dssetup__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_dssetup.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_dssetup.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_dssetup.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_dssetup.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_dssetup, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dssetup__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct dssetup_DsRoleGetPrimaryDomainInformation *r2 = (struct dssetup_DsRoleGetPrimaryDomainInformation *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetPrimaryDomainInformation, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleGetPrimaryDomainInformation(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetPrimaryDomainInformation will reply async\n"));
		}
		break;
	}
	case 1: {
		struct dssetup_DsRoleDnsNameToFlatName *r2 = (struct dssetup_DsRoleDnsNameToFlatName *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDnsNameToFlatName, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleDnsNameToFlatName(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDnsNameToFlatName will reply async\n"));
		}
		break;
	}
	case 2: {
		struct dssetup_DsRoleDcAsDc *r2 = (struct dssetup_DsRoleDcAsDc *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDcAsDc, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleDcAsDc(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDcAsDc will reply async\n"));
		}
		break;
	}
	case 3: {
		struct dssetup_DsRoleDcAsReplica *r2 = (struct dssetup_DsRoleDcAsReplica *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDcAsReplica, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleDcAsReplica(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDcAsReplica will reply async\n"));
		}
		break;
	}
	case 4: {
		struct dssetup_DsRoleDemoteDc *r2 = (struct dssetup_DsRoleDemoteDc *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDemoteDc, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleDemoteDc(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDemoteDc will reply async\n"));
		}
		break;
	}
	case 5: {
		struct dssetup_DsRoleGetDcOperationProgress *r2 = (struct dssetup_DsRoleGetDcOperationProgress *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetDcOperationProgress, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleGetDcOperationProgress(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetDcOperationProgress will reply async\n"));
		}
		break;
	}
	case 6: {
		struct dssetup_DsRoleGetDcOperationResults *r2 = (struct dssetup_DsRoleGetDcOperationResults *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetDcOperationResults, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleGetDcOperationResults(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetDcOperationResults will reply async\n"));
		}
		break;
	}
	case 7: {
		struct dssetup_DsRoleCancel *r2 = (struct dssetup_DsRoleCancel *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleCancel, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleCancel(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleCancel will reply async\n"));
		}
		break;
	}
	case 8: {
		struct dssetup_DsRoleServerSaveStateForUpgrade *r2 = (struct dssetup_DsRoleServerSaveStateForUpgrade *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleServerSaveStateForUpgrade, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleServerSaveStateForUpgrade(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleServerSaveStateForUpgrade will reply async\n"));
		}
		break;
	}
	case 9: {
		struct dssetup_DsRoleUpgradeDownlevelServer *r2 = (struct dssetup_DsRoleUpgradeDownlevelServer *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleUpgradeDownlevelServer, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleUpgradeDownlevelServer(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleUpgradeDownlevelServer will reply async\n"));
		}
		break;
	}
	case 10: {
		struct dssetup_DsRoleAbortDownlevelServerUpgrade *r2 = (struct dssetup_DsRoleAbortDownlevelServerUpgrade *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleAbortDownlevelServerUpgrade, NDR_IN, r2);
		}
		r2->out.result = dcesrv_dssetup_DsRoleAbortDownlevelServerUpgrade(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleAbortDownlevelServerUpgrade will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_dssetup, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dssetup__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct dssetup_DsRoleGetPrimaryDomainInformation *r2 = (struct dssetup_DsRoleGetPrimaryDomainInformation *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetPrimaryDomainInformation replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetPrimaryDomainInformation, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleGetPrimaryDomainInformation\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 1: {
		struct dssetup_DsRoleDnsNameToFlatName *r2 = (struct dssetup_DsRoleDnsNameToFlatName *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDnsNameToFlatName replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDnsNameToFlatName, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleDnsNameToFlatName\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 2: {
		struct dssetup_DsRoleDcAsDc *r2 = (struct dssetup_DsRoleDcAsDc *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDcAsDc replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDcAsDc, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleDcAsDc\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 3: {
		struct dssetup_DsRoleDcAsReplica *r2 = (struct dssetup_DsRoleDcAsReplica *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDcAsReplica replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDcAsReplica, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleDcAsReplica\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 4: {
		struct dssetup_DsRoleDemoteDc *r2 = (struct dssetup_DsRoleDemoteDc *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleDemoteDc replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleDemoteDc, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleDemoteDc\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 5: {
		struct dssetup_DsRoleGetDcOperationProgress *r2 = (struct dssetup_DsRoleGetDcOperationProgress *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetDcOperationProgress replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetDcOperationProgress, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleGetDcOperationProgress\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 6: {
		struct dssetup_DsRoleGetDcOperationResults *r2 = (struct dssetup_DsRoleGetDcOperationResults *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleGetDcOperationResults replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleGetDcOperationResults, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleGetDcOperationResults\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 7: {
		struct dssetup_DsRoleCancel *r2 = (struct dssetup_DsRoleCancel *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleCancel replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleCancel, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleCancel\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 8: {
		struct dssetup_DsRoleServerSaveStateForUpgrade *r2 = (struct dssetup_DsRoleServerSaveStateForUpgrade *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleServerSaveStateForUpgrade replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleServerSaveStateForUpgrade, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleServerSaveStateForUpgrade\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 9: {
		struct dssetup_DsRoleUpgradeDownlevelServer *r2 = (struct dssetup_DsRoleUpgradeDownlevelServer *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleUpgradeDownlevelServer replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleUpgradeDownlevelServer, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleUpgradeDownlevelServer\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 10: {
		struct dssetup_DsRoleAbortDownlevelServerUpgrade *r2 = (struct dssetup_DsRoleAbortDownlevelServerUpgrade *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function dssetup_DsRoleAbortDownlevelServerUpgrade replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(dssetup_DsRoleAbortDownlevelServerUpgrade, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in dssetup_DsRoleAbortDownlevelServerUpgrade\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_dssetup, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dssetup__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_dssetup.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_dssetup_interface = {
	.name		    = "dssetup",
	.syntax_id          = {{0x3919286a,0xb10c,0x11d0,{0x9b,0xa8},{0x00,0xc0,0x4f,0xd9,0x2e,0xf5}},0.0},
	.bind		    = dssetup__op_bind,
	.unbind		    = dssetup__op_unbind,
	.ndr_pull	    = dssetup__op_ndr_pull,
	.dispatch	    = dssetup__op_dispatch,
	.reply		    = dssetup__op_reply,
	.ndr_push	    = dssetup__op_ndr_push,
#ifdef DCESRV_INTERFACE_DSSETUP_FLAGS
	.flags              = DCESRV_INTERFACE_DSSETUP_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS dssetup__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_dssetup.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_dssetup.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_dssetup_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("dssetup_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool dssetup__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_dssetup_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_dssetup_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_dssetup_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool dssetup__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_dssetup_interface.name, name)==0) {
		memcpy(iface, &dcesrv_dssetup_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_dssetup_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "dssetup",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_DSSETUP_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_DSSETUP_INIT_SERVER,
#else
	    .init_server = dssetup__op_init_server,
#endif
	    .interface_by_uuid = dssetup__op_interface_by_uuid,
	    .interface_by_name = dssetup__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'dssetup' endpoint server!\n"));
		return ret;
	}

	return ret;
}
