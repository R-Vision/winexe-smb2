/* header auto-generated by pidl */

#include "librpc/ndr/libndr.h"
#include "bin/default/librpc/gen_ndr/frsrpc.h"

#ifndef _HEADER_NDR_frsrpc
#define _HEADER_NDR_frsrpc

#include "../librpc/ndr/ndr_frsrpc.h"
#define NDR_FRSRPC_UUID "f5cc59b4-4264-101a-8c59-08002b2f8426"
#define NDR_FRSRPC_VERSION 65537
#define NDR_FRSRPC_NAME "frsrpc"
#define NDR_FRSRPC_HELPSTRING "File Replication Service"
extern const struct ndr_interface_table ndr_table_frsrpc;
#define NDR_FRSRPC_FRSSENDCOMMPKT (0x00)

#define NDR_FRSRPC_FRSVERIFYPROMOTIONPARENT (0x01)

#define NDR_FRSRPC_FRSSTARTPROMOTIONPARENT (0x02)

#define NDR_FRSRPC_FRSNOP (0x03)

#define NDR_FRSRPC_CALL_COUNT (4)
void ndr_print_frsrpc_CommPktChunkGuidName(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktChunkGuidName *r);
void ndr_print_frsrpc_CommPktGSVN(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktGSVN *r);
void ndr_print_frsrpc_CommPktCoCmdFlags(struct ndr_print *ndr, const char *name, uint32_t r);
void ndr_print_frsrpc_CommPktCoCmdIFlags(struct ndr_print *ndr, const char *name, uint32_t r);
void ndr_print_frsrpc_CommPktCoCmdStatus(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktCoCmdStatus r);
void ndr_print_frsrpc_CommPktCoCmdContentCmd(struct ndr_print *ndr, const char *name, uint32_t r);
void ndr_print_frsrpc_CommPktCoCmdLocationCmd(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktCoCmdLocationCmd r);
enum ndr_err_code ndr_push_frsrpc_CommPktChangeOrderCommand(struct ndr_push *ndr, int ndr_flags, const struct frsrpc_CommPktChangeOrderCommand *r);
enum ndr_err_code ndr_pull_frsrpc_CommPktChangeOrderCommand(struct ndr_pull *ndr, int ndr_flags, struct frsrpc_CommPktChangeOrderCommand *r);
void ndr_print_frsrpc_CommPktChangeOrderCommand(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktChangeOrderCommand *r);
void ndr_print_frsrpc_CommPktDataExtensionType(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktDataExtensionType r);
void ndr_print_frsrpc_CommPktDataExtensionChecksum(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktDataExtensionChecksum *r);
void ndr_print_frsrpc_CommPktDataExtensionRetryTimeout(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktDataExtensionRetryTimeout *r);
void ndr_print_frsrpc_CommPktCoRecordExtensionMajor(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktCoRecordExtensionMajor r);
void ndr_print_frsrpc_CommPktCoRecordExtensionWin2k(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktCoRecordExtensionWin2k *r);
void ndr_print_frsrpc_CommPktChangeOrderRecordExtension(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktChangeOrderRecordExtension *r);
void ndr_print_frsrpc_CommPktCommand(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktCommand r);
void ndr_print_frsrpc_CommPktChunkType(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktChunkType r);
void ndr_print_frsrpc_CommPktChunkData(struct ndr_print *ndr, const char *name, const union frsrpc_CommPktChunkData *r);
enum ndr_err_code ndr_push_frsrpc_CommPktChunk(struct ndr_push *ndr, int ndr_flags, const struct frsrpc_CommPktChunk *r);
enum ndr_err_code ndr_pull_frsrpc_CommPktChunk(struct ndr_pull *ndr, int ndr_flags, struct frsrpc_CommPktChunk *r);
void ndr_print_frsrpc_CommPktChunk(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktChunk *r);
enum ndr_err_code ndr_push_frsrpc_CommPktChunkCtr(struct ndr_push *ndr, int ndr_flags, const struct frsrpc_CommPktChunkCtr *r);
enum ndr_err_code ndr_pull_frsrpc_CommPktChunkCtr(struct ndr_pull *ndr, int ndr_flags, struct frsrpc_CommPktChunkCtr *r);
void ndr_print_frsrpc_CommPktChunkCtr(struct ndr_print *ndr, const char *name, const struct frsrpc_CommPktChunkCtr *r);
void ndr_print_frsrpc_CommPktMajor(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktMajor r);
void ndr_print_frsrpc_CommPktMinor(struct ndr_print *ndr, const char *name, enum frsrpc_CommPktMinor r);
enum ndr_err_code ndr_push_frsrpc_FrsSendCommPktReq(struct ndr_push *ndr, int ndr_flags, const struct frsrpc_FrsSendCommPktReq *r);
enum ndr_err_code ndr_pull_frsrpc_FrsSendCommPktReq(struct ndr_pull *ndr, int ndr_flags, struct frsrpc_FrsSendCommPktReq *r);
void ndr_print_frsrpc_FrsSendCommPktReq(struct ndr_print *ndr, const char *name, const struct frsrpc_FrsSendCommPktReq *r);
void ndr_print_frsrpc_PartnerAuthLevel(struct ndr_print *ndr, const char *name, enum frsrpc_PartnerAuthLevel r);
enum ndr_err_code ndr_push_frsrpc_StageHeader(struct ndr_push *ndr, int ndr_flags, const struct frsrpc_StageHeader *r);
enum ndr_err_code ndr_pull_frsrpc_StageHeader(struct ndr_pull *ndr, int ndr_flags, struct frsrpc_StageHeader *r);
void ndr_print_frsrpc_StageHeader(struct ndr_print *ndr, const char *name, const struct frsrpc_StageHeader *r);
void ndr_print_frsrpc_FrsSendCommPkt(struct ndr_print *ndr, const char *name, int flags, const struct frsrpc_FrsSendCommPkt *r);
void ndr_print_frsrpc_FrsVerifyPromotionParent(struct ndr_print *ndr, const char *name, int flags, const struct frsrpc_FrsVerifyPromotionParent *r);
void ndr_print_frsrpc_FrsStartPromotionParent(struct ndr_print *ndr, const char *name, int flags, const struct frsrpc_FrsStartPromotionParent *r);
void ndr_print_frsrpc_FrsNOP(struct ndr_print *ndr, const char *name, int flags, const struct frsrpc_FrsNOP *r);
#endif /* _HEADER_NDR_frsrpc */
