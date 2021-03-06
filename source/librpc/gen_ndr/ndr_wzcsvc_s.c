/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_wzcsvc.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_wzcsvc_init(TALLOC_CTX *);

/* wzcsvc - dcerpc server boilerplate generated by pidl */


static NTSTATUS wzcsvc__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_WZCSVC_BIND
	return DCESRV_INTERFACE_WZCSVC_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void wzcsvc__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_WZCSVC_UNBIND
	DCESRV_INTERFACE_WZCSVC_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS wzcsvc__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_wzcsvc.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_wzcsvc.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_wzcsvc.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_wzcsvc.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_wzcsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wzcsvc__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct wzcsvc_EnumInterfaces *r2 = (struct wzcsvc_EnumInterfaces *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EnumInterfaces, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EnumInterfaces(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EnumInterfaces will reply async\n"));
		}
		break;
	}
	case 1: {
		struct wzcsvc_QueryInterface *r2 = (struct wzcsvc_QueryInterface *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_QueryInterface, NDR_IN, r2);
		}
		dcesrv_wzcsvc_QueryInterface(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_QueryInterface will reply async\n"));
		}
		break;
	}
	case 2: {
		struct wzcsvc_SetInterface *r2 = (struct wzcsvc_SetInterface *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_SetInterface, NDR_IN, r2);
		}
		dcesrv_wzcsvc_SetInterface(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_SetInterface will reply async\n"));
		}
		break;
	}
	case 3: {
		struct wzcsvc_RefreshInterface *r2 = (struct wzcsvc_RefreshInterface *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_RefreshInterface, NDR_IN, r2);
		}
		dcesrv_wzcsvc_RefreshInterface(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_RefreshInterface will reply async\n"));
		}
		break;
	}
	case 4: {
		struct wzcsvc_QueryContext *r2 = (struct wzcsvc_QueryContext *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_QueryContext, NDR_IN, r2);
		}
		dcesrv_wzcsvc_QueryContext(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_QueryContext will reply async\n"));
		}
		break;
	}
	case 5: {
		struct wzcsvc_SetContext *r2 = (struct wzcsvc_SetContext *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_SetContext, NDR_IN, r2);
		}
		dcesrv_wzcsvc_SetContext(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_SetContext will reply async\n"));
		}
		break;
	}
	case 6: {
		struct wzcsvc_EapolUIResponse *r2 = (struct wzcsvc_EapolUIResponse *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolUIResponse, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolUIResponse(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolUIResponse will reply async\n"));
		}
		break;
	}
	case 7: {
		struct wzcsvc_EapolGetCustomAuthData *r2 = (struct wzcsvc_EapolGetCustomAuthData *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolGetCustomAuthData, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolGetCustomAuthData(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolGetCustomAuthData will reply async\n"));
		}
		break;
	}
	case 8: {
		struct wzcsvc_EapolSetCustomAuthData *r2 = (struct wzcsvc_EapolSetCustomAuthData *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolSetCustomAuthData, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolSetCustomAuthData(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolSetCustomAuthData will reply async\n"));
		}
		break;
	}
	case 9: {
		struct wzcsvc_EapolGetInterfaceParams *r2 = (struct wzcsvc_EapolGetInterfaceParams *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolGetInterfaceParams, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolGetInterfaceParams(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolGetInterfaceParams will reply async\n"));
		}
		break;
	}
	case 10: {
		struct wzcsvc_EapolSetInterfaceParams *r2 = (struct wzcsvc_EapolSetInterfaceParams *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolSetInterfaceParams, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolSetInterfaceParams(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolSetInterfaceParams will reply async\n"));
		}
		break;
	}
	case 11: {
		struct wzcsvc_EapolReAuthenticateInterface *r2 = (struct wzcsvc_EapolReAuthenticateInterface *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolReAuthenticateInterface, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolReAuthenticateInterface(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolReAuthenticateInterface will reply async\n"));
		}
		break;
	}
	case 12: {
		struct wzcsvc_EapolQueryInterfaceState *r2 = (struct wzcsvc_EapolQueryInterfaceState *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolQueryInterfaceState, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EapolQueryInterfaceState(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolQueryInterfaceState will reply async\n"));
		}
		break;
	}
	case 13: {
		struct wzcsvc_OpenWZCDbLogSession *r2 = (struct wzcsvc_OpenWZCDbLogSession *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_OpenWZCDbLogSession, NDR_IN, r2);
		}
		dcesrv_wzcsvc_OpenWZCDbLogSession(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_OpenWZCDbLogSession will reply async\n"));
		}
		break;
	}
	case 14: {
		struct wzcsvc_CloseWZCDbLogSession *r2 = (struct wzcsvc_CloseWZCDbLogSession *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_CloseWZCDbLogSession, NDR_IN, r2);
		}
		dcesrv_wzcsvc_CloseWZCDbLogSession(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_CloseWZCDbLogSession will reply async\n"));
		}
		break;
	}
	case 15: {
		struct wzcsvc_EnumWZCDbLogRecords *r2 = (struct wzcsvc_EnumWZCDbLogRecords *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EnumWZCDbLogRecords, NDR_IN, r2);
		}
		dcesrv_wzcsvc_EnumWZCDbLogRecords(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EnumWZCDbLogRecords will reply async\n"));
		}
		break;
	}
	case 16: {
		struct wzcsvc_FlushWZCdbLog *r2 = (struct wzcsvc_FlushWZCdbLog *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_FlushWZCdbLog, NDR_IN, r2);
		}
		dcesrv_wzcsvc_FlushWZCdbLog(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_FlushWZCdbLog will reply async\n"));
		}
		break;
	}
	case 17: {
		struct wzcsvc_GetWZCDbLogRecord *r2 = (struct wzcsvc_GetWZCDbLogRecord *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_GetWZCDbLogRecord, NDR_IN, r2);
		}
		dcesrv_wzcsvc_GetWZCDbLogRecord(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_GetWZCDbLogRecord will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_wzcsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wzcsvc__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct wzcsvc_EnumInterfaces *r2 = (struct wzcsvc_EnumInterfaces *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EnumInterfaces replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EnumInterfaces, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EnumInterfaces\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 1: {
		struct wzcsvc_QueryInterface *r2 = (struct wzcsvc_QueryInterface *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_QueryInterface replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_QueryInterface, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_QueryInterface\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 2: {
		struct wzcsvc_SetInterface *r2 = (struct wzcsvc_SetInterface *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_SetInterface replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_SetInterface, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_SetInterface\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 3: {
		struct wzcsvc_RefreshInterface *r2 = (struct wzcsvc_RefreshInterface *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_RefreshInterface replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_RefreshInterface, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_RefreshInterface\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 4: {
		struct wzcsvc_QueryContext *r2 = (struct wzcsvc_QueryContext *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_QueryContext replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_QueryContext, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_QueryContext\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 5: {
		struct wzcsvc_SetContext *r2 = (struct wzcsvc_SetContext *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_SetContext replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_SetContext, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_SetContext\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 6: {
		struct wzcsvc_EapolUIResponse *r2 = (struct wzcsvc_EapolUIResponse *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolUIResponse replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolUIResponse, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolUIResponse\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 7: {
		struct wzcsvc_EapolGetCustomAuthData *r2 = (struct wzcsvc_EapolGetCustomAuthData *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolGetCustomAuthData replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolGetCustomAuthData, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolGetCustomAuthData\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 8: {
		struct wzcsvc_EapolSetCustomAuthData *r2 = (struct wzcsvc_EapolSetCustomAuthData *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolSetCustomAuthData replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolSetCustomAuthData, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolSetCustomAuthData\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 9: {
		struct wzcsvc_EapolGetInterfaceParams *r2 = (struct wzcsvc_EapolGetInterfaceParams *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolGetInterfaceParams replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolGetInterfaceParams, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolGetInterfaceParams\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 10: {
		struct wzcsvc_EapolSetInterfaceParams *r2 = (struct wzcsvc_EapolSetInterfaceParams *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolSetInterfaceParams replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolSetInterfaceParams, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolSetInterfaceParams\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 11: {
		struct wzcsvc_EapolReAuthenticateInterface *r2 = (struct wzcsvc_EapolReAuthenticateInterface *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolReAuthenticateInterface replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolReAuthenticateInterface, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolReAuthenticateInterface\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 12: {
		struct wzcsvc_EapolQueryInterfaceState *r2 = (struct wzcsvc_EapolQueryInterfaceState *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EapolQueryInterfaceState replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EapolQueryInterfaceState, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EapolQueryInterfaceState\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 13: {
		struct wzcsvc_OpenWZCDbLogSession *r2 = (struct wzcsvc_OpenWZCDbLogSession *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_OpenWZCDbLogSession replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_OpenWZCDbLogSession, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_OpenWZCDbLogSession\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 14: {
		struct wzcsvc_CloseWZCDbLogSession *r2 = (struct wzcsvc_CloseWZCDbLogSession *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_CloseWZCDbLogSession replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_CloseWZCDbLogSession, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_CloseWZCDbLogSession\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 15: {
		struct wzcsvc_EnumWZCDbLogRecords *r2 = (struct wzcsvc_EnumWZCDbLogRecords *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_EnumWZCDbLogRecords replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_EnumWZCDbLogRecords, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_EnumWZCDbLogRecords\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 16: {
		struct wzcsvc_FlushWZCdbLog *r2 = (struct wzcsvc_FlushWZCdbLog *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_FlushWZCdbLog replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_FlushWZCdbLog, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_FlushWZCdbLog\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 17: {
		struct wzcsvc_GetWZCDbLogRecord *r2 = (struct wzcsvc_GetWZCDbLogRecord *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function wzcsvc_GetWZCDbLogRecord replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(wzcsvc_GetWZCDbLogRecord, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in wzcsvc_GetWZCDbLogRecord\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_wzcsvc, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wzcsvc__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_wzcsvc.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_wzcsvc_interface = {
	.name		    = "wzcsvc",
	.syntax_id          = {{0x621dff68,0x3c39,0x4c6c,{0xaa,0xe3},{0xe6,0x8e,0x2c,0x65,0x03,0xad}},1.0},
	.bind		    = wzcsvc__op_bind,
	.unbind		    = wzcsvc__op_unbind,
	.ndr_pull	    = wzcsvc__op_ndr_pull,
	.dispatch	    = wzcsvc__op_dispatch,
	.reply		    = wzcsvc__op_reply,
	.ndr_push	    = wzcsvc__op_ndr_push,
#ifdef DCESRV_INTERFACE_WZCSVC_FLAGS
	.flags              = DCESRV_INTERFACE_WZCSVC_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS wzcsvc__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_wzcsvc.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_wzcsvc.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_wzcsvc_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("wzcsvc_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool wzcsvc__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_wzcsvc_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_wzcsvc_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_wzcsvc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool wzcsvc__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_wzcsvc_interface.name, name)==0) {
		memcpy(iface, &dcesrv_wzcsvc_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_wzcsvc_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "wzcsvc",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_WZCSVC_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_WZCSVC_INIT_SERVER,
#else
	    .init_server = wzcsvc__op_init_server,
#endif
	    .interface_by_uuid = wzcsvc__op_interface_by_uuid,
	    .interface_by_name = wzcsvc__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'wzcsvc' endpoint server!\n"));
		return ret;
	}

	return ret;
}

