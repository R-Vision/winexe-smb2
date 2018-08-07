/* server functions auto-generated by pidl */
#include "bin/default/librpc/gen_ndr/ndr_frstrans.h"
#include <util/debug.h>

NTSTATUS dcerpc_server_frstrans_init(TALLOC_CTX *);

/* frstrans - dcerpc server boilerplate generated by pidl */


static NTSTATUS frstrans__op_bind(struct dcesrv_call_state *dce_call, const struct dcesrv_interface *iface, uint32_t if_version)
{
#ifdef DCESRV_INTERFACE_FRSTRANS_BIND
	return DCESRV_INTERFACE_FRSTRANS_BIND(dce_call,iface);
#else
	return NT_STATUS_OK;
#endif
}

static void frstrans__op_unbind(struct dcesrv_connection_context *context, const struct dcesrv_interface *iface)
{
#ifdef DCESRV_INTERFACE_FRSTRANS_UNBIND
	DCESRV_INTERFACE_FRSTRANS_UNBIND(context, iface);
#else
	return;
#endif
}

static NTSTATUS frstrans__op_ndr_pull(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_pull *pull, void **r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	dce_call->fault_code = 0;

	if (opnum >= ndr_table_frstrans.num_calls) {
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	*r = talloc_named(mem_ctx,
			  ndr_table_frstrans.calls[opnum].struct_size,
			  "struct %s",
			  ndr_table_frstrans.calls[opnum].name);
	NT_STATUS_HAVE_NO_MEMORY(*r);

        /* unravel the NDR for the packet */
	ndr_err = ndr_table_frstrans.calls[opnum].ndr_pull(pull, NDR_IN, *r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
				  &ndr_table_frstrans, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frstrans__op_dispatch(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct frstrans_CheckConnectivity *r2 = (struct frstrans_CheckConnectivity *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_CheckConnectivity, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_CheckConnectivity(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_CheckConnectivity will reply async\n"));
		}
		break;
	}
	case 1: {
		struct frstrans_EstablishConnection *r2 = (struct frstrans_EstablishConnection *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_EstablishConnection, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_EstablishConnection(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_EstablishConnection will reply async\n"));
		}
		break;
	}
	case 2: {
		struct frstrans_EstablishSession *r2 = (struct frstrans_EstablishSession *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_EstablishSession, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_EstablishSession(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_EstablishSession will reply async\n"));
		}
		break;
	}
	case 3: {
		struct frstrans_RequestUpdates *r2 = (struct frstrans_RequestUpdates *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RequestUpdates, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_RequestUpdates(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RequestUpdates will reply async\n"));
		}
		break;
	}
	case 4: {
		struct frstrans_RequestVersionVector *r2 = (struct frstrans_RequestVersionVector *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RequestVersionVector, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_RequestVersionVector(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RequestVersionVector will reply async\n"));
		}
		break;
	}
	case 5: {
		struct frstrans_AsyncPoll *r2 = (struct frstrans_AsyncPoll *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_AsyncPoll, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_AsyncPoll(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_AsyncPoll will reply async\n"));
		}
		break;
	}
	case 6: {
		struct FRSTRANS_REQUEST_RECORDS *r2 = (struct FRSTRANS_REQUEST_RECORDS *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_REQUEST_RECORDS, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_REQUEST_RECORDS(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_REQUEST_RECORDS will reply async\n"));
		}
		break;
	}
	case 7: {
		struct FRSTRANS_UPDATE_CANCEL *r2 = (struct FRSTRANS_UPDATE_CANCEL *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_UPDATE_CANCEL, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_UPDATE_CANCEL(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_UPDATE_CANCEL will reply async\n"));
		}
		break;
	}
	case 8: {
		struct FRSTRANS_RAW_GET_FILE_DATA *r2 = (struct FRSTRANS_RAW_GET_FILE_DATA *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RAW_GET_FILE_DATA, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_RAW_GET_FILE_DATA(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RAW_GET_FILE_DATA will reply async\n"));
		}
		break;
	}
	case 9: {
		struct FRSTRANS_RDC_GET_SIGNATURES *r2 = (struct FRSTRANS_RDC_GET_SIGNATURES *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_GET_SIGNATURES, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_RDC_GET_SIGNATURES(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_GET_SIGNATURES will reply async\n"));
		}
		break;
	}
	case 10: {
		struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *r2 = (struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_PUSH_SOURCE_NEEDS, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_RDC_PUSH_SOURCE_NEEDS(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_PUSH_SOURCE_NEEDS will reply async\n"));
		}
		break;
	}
	case 11: {
		struct FRSTRANS_RDC_GET_FILE_DATA *r2 = (struct FRSTRANS_RDC_GET_FILE_DATA *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_GET_FILE_DATA, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_RDC_GET_FILE_DATA(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_GET_FILE_DATA will reply async\n"));
		}
		break;
	}
	case 12: {
		struct frstrans_RdcClose *r2 = (struct frstrans_RdcClose *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RdcClose, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_RdcClose(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RdcClose will reply async\n"));
		}
		break;
	}
	case 13: {
		struct frstrans_InitializeFileTransferAsync *r2 = (struct frstrans_InitializeFileTransferAsync *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_InitializeFileTransferAsync, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_InitializeFileTransferAsync(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_InitializeFileTransferAsync will reply async\n"));
		}
		break;
	}
	case 14: {
		struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *r2 = (struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE, NDR_IN, r2);
		}
		dcesrv_FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE will reply async\n"));
		}
		break;
	}
	case 15: {
		struct frstrans_RawGetFileDataAsync *r2 = (struct frstrans_RawGetFileDataAsync *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RawGetFileDataAsync, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_RawGetFileDataAsync(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RawGetFileDataAsync will reply async\n"));
		}
		break;
	}
	case 16: {
		struct frstrans_RdcGetFileDataAsync *r2 = (struct frstrans_RdcGetFileDataAsync *)r;
		if (DEBUGLEVEL >= 10) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RdcGetFileDataAsync, NDR_IN, r2);
		}
		r2->out.result = dcesrv_frstrans_RdcGetFileDataAsync(dce_call, mem_ctx, r2);
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RdcGetFileDataAsync will reply async\n"));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir, 
		          &ndr_table_frstrans, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frstrans__op_reply(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, void *r)
{
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	switch (opnum) {
	case 0: {
		struct frstrans_CheckConnectivity *r2 = (struct frstrans_CheckConnectivity *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_CheckConnectivity replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_CheckConnectivity, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_CheckConnectivity\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 1: {
		struct frstrans_EstablishConnection *r2 = (struct frstrans_EstablishConnection *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_EstablishConnection replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_EstablishConnection, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_EstablishConnection\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 2: {
		struct frstrans_EstablishSession *r2 = (struct frstrans_EstablishSession *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_EstablishSession replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_EstablishSession, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_EstablishSession\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 3: {
		struct frstrans_RequestUpdates *r2 = (struct frstrans_RequestUpdates *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RequestUpdates replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RequestUpdates, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_RequestUpdates\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 4: {
		struct frstrans_RequestVersionVector *r2 = (struct frstrans_RequestVersionVector *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RequestVersionVector replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RequestVersionVector, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_RequestVersionVector\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 5: {
		struct frstrans_AsyncPoll *r2 = (struct frstrans_AsyncPoll *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_AsyncPoll replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_AsyncPoll, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_AsyncPoll\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 6: {
		struct FRSTRANS_REQUEST_RECORDS *r2 = (struct FRSTRANS_REQUEST_RECORDS *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_REQUEST_RECORDS replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_REQUEST_RECORDS, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_REQUEST_RECORDS\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 7: {
		struct FRSTRANS_UPDATE_CANCEL *r2 = (struct FRSTRANS_UPDATE_CANCEL *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_UPDATE_CANCEL replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_UPDATE_CANCEL, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_UPDATE_CANCEL\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 8: {
		struct FRSTRANS_RAW_GET_FILE_DATA *r2 = (struct FRSTRANS_RAW_GET_FILE_DATA *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RAW_GET_FILE_DATA replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RAW_GET_FILE_DATA, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_RAW_GET_FILE_DATA\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 9: {
		struct FRSTRANS_RDC_GET_SIGNATURES *r2 = (struct FRSTRANS_RDC_GET_SIGNATURES *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_GET_SIGNATURES replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_GET_SIGNATURES, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_RDC_GET_SIGNATURES\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 10: {
		struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *r2 = (struct FRSTRANS_RDC_PUSH_SOURCE_NEEDS *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_PUSH_SOURCE_NEEDS replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_PUSH_SOURCE_NEEDS, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_RDC_PUSH_SOURCE_NEEDS\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 11: {
		struct FRSTRANS_RDC_GET_FILE_DATA *r2 = (struct FRSTRANS_RDC_GET_FILE_DATA *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_RDC_GET_FILE_DATA replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_RDC_GET_FILE_DATA, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_RDC_GET_FILE_DATA\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 12: {
		struct frstrans_RdcClose *r2 = (struct frstrans_RdcClose *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RdcClose replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RdcClose, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_RdcClose\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 13: {
		struct frstrans_InitializeFileTransferAsync *r2 = (struct frstrans_InitializeFileTransferAsync *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_InitializeFileTransferAsync replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_InitializeFileTransferAsync, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_InitializeFileTransferAsync\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 14: {
		struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *r2 = (struct FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in FRSTRANS_OPNUM_0E_NOT_USED_ON_THE_WIRE\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 15: {
		struct frstrans_RawGetFileDataAsync *r2 = (struct frstrans_RawGetFileDataAsync *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RawGetFileDataAsync replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RawGetFileDataAsync, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_RawGetFileDataAsync\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}
	case 16: {
		struct frstrans_RdcGetFileDataAsync *r2 = (struct frstrans_RdcGetFileDataAsync *)r;
		if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
			DEBUG(5,("function frstrans_RdcGetFileDataAsync replied async\n"));
		}
		if (DEBUGLEVEL >= 10 && dce_call->fault_code == 0) {
			NDR_PRINT_FUNCTION_DEBUG(frstrans_RdcGetFileDataAsync, NDR_OUT | NDR_SET_VALUES, r2);
		}
		if (dce_call->fault_code != 0) {
			DEBUG(2,("dcerpc_fault %s in frstrans_RdcGetFileDataAsync\n", dcerpc_errstr(mem_ctx, dce_call->fault_code)));
		}
		break;
	}

	default:
		dce_call->fault_code = DCERPC_FAULT_OP_RNG_ERROR;
		break;
	}

	if (dce_call->fault_code != 0) {
		dcerpc_log_packet(dce_call->conn->packet_log_dir,
		          &ndr_table_frstrans, opnum, NDR_IN,
				  &dce_call->pkt.u.request.stub_and_verifier);
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static NTSTATUS frstrans__op_ndr_push(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx, struct ndr_push *push, const void *r)
{
	enum ndr_err_code ndr_err;
	uint16_t opnum = dce_call->pkt.u.request.opnum;

	ndr_err = ndr_table_frstrans.calls[opnum].ndr_push(push, NDR_OUT, r);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		dce_call->fault_code = DCERPC_FAULT_NDR;
		return NT_STATUS_NET_WRITE_FAULT;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_interface dcesrv_frstrans_interface = {
	.name		    = "frstrans",
	.syntax_id          = {{0x897e2e5f,0x93f3,0x4376,{0x9c,0x9c},{0xfd,0x22,0x77,0x49,0x5c,0x27}},1.0},
	.bind		    = frstrans__op_bind,
	.unbind		    = frstrans__op_unbind,
	.ndr_pull	    = frstrans__op_ndr_pull,
	.dispatch	    = frstrans__op_dispatch,
	.reply		    = frstrans__op_reply,
	.ndr_push	    = frstrans__op_ndr_push,
#ifdef DCESRV_INTERFACE_FRSTRANS_FLAGS
	.flags              = DCESRV_INTERFACE_FRSTRANS_FLAGS
#else
	.flags              = 0
#endif
};


static NTSTATUS frstrans__op_init_server(struct dcesrv_context *dce_ctx, const struct dcesrv_endpoint_server *ep_server)
{
	int i;

	for (i=0;i<ndr_table_frstrans.endpoints->count;i++) {
		NTSTATUS ret;
		const char *name = ndr_table_frstrans.endpoints->names[i];

		ret = dcesrv_interface_register(dce_ctx, name, &dcesrv_frstrans_interface, NULL);
		if (!NT_STATUS_IS_OK(ret)) {
			DEBUG(1,("frstrans_op_init_server: failed to register endpoint '%s'\n",name));
			return ret;
		}
	}

	return NT_STATUS_OK;
}

static bool frstrans__op_interface_by_uuid(struct dcesrv_interface *iface, const struct GUID *uuid, uint32_t if_version)
{
	if (dcesrv_frstrans_interface.syntax_id.if_version == if_version &&
		GUID_equal(&dcesrv_frstrans_interface.syntax_id.uuid, uuid)) {
		memcpy(iface,&dcesrv_frstrans_interface, sizeof(*iface));
		return true;
	}

	return false;
}

static bool frstrans__op_interface_by_name(struct dcesrv_interface *iface, const char *name)
{
	if (strcmp(dcesrv_frstrans_interface.name, name)==0) {
		memcpy(iface, &dcesrv_frstrans_interface, sizeof(*iface));
		return true;
	}

	return false;
}

NTSTATUS dcerpc_server_frstrans_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;
	static const struct dcesrv_endpoint_server ep_server = {
	    /* fill in our name */
	    .name = "frstrans",

	    /* fill in all the operations */
#ifdef DCESRV_INTERFACE_FRSTRANS_INIT_SERVER
	    .init_server = DCESRV_INTERFACE_FRSTRANS_INIT_SERVER,
#else
	    .init_server = frstrans__op_init_server,
#endif
	    .interface_by_uuid = frstrans__op_interface_by_uuid,
	    .interface_by_name = frstrans__op_interface_by_name
	};
	/* register ourselves with the DCERPC subsystem. */
	ret = dcerpc_register_ep_server(&ep_server);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'frstrans' endpoint server!\n"));
		return ret;
	}

	return ret;
}

