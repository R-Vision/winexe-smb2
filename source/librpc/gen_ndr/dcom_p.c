#include "includes.h"
#include "lib/com/dcom/dcom.h"
#include "bin/default/librpc/gen_ndr/com_dcom.h"
#include "librpc/rpc/dcerpc.h"
/* DCOM proxy for IUnknown generated by pidl */


static WERROR dcom_proxy_IUnknown_QueryInterface(struct IUnknown *d, TALLOC_CTX *mem_ctx, struct GUID *iid, struct IUnknown **data)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct QueryInterface r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.iid = iid;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(QueryInterface, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IUnknown, NDR_QUERYINTERFACE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(QueryInterface, r);		
	}

	NDR_CHECK(dcom_IUnknown_from_OBJREF(d->ctx, &data, r.out.data.obj));

	return r.out.result;
}


static uint32_t dcom_proxy_IUnknown_AddRef(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct AddRef r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(AddRef, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IUnknown, NDR_ADDREF, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(AddRef, r);		
	}


	return r.out.result;
}


static uint32_t dcom_proxy_IUnknown_Release(struct IUnknown *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct Release r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(Release, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IUnknown, NDR_RELEASE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(Release, r);		
	}


	return r.out.result;
}

static NTSTATUS dcom_proxy_IUnknown_init(TALLOC_CTX *ctx)
{
	struct IUnknown_vtable *proxy_vtable = talloc(ctx, struct IUnknown_vtable);
	proxy_vtable->QueryInterface = dcom_proxy_IUnknown_QueryInterface;
	proxy_vtable->AddRef = dcom_proxy_IUnknown_AddRef;
	proxy_vtable->Release = dcom_proxy_IUnknown_Release;

	proxy_vtable->iid = ndr_table_IUnknown.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IClassFactory generated by pidl */


static WERROR dcom_proxy_IClassFactory_CreateInstance(struct IClassFactory *d, TALLOC_CTX *mem_ctx, struct MInterfacePointer *pUnknown, struct GUID *iid, struct MInterfacePointer *ppv)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct CreateInstance r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.pUnknown = pUnknown;
	r.in.iid = iid;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(CreateInstance, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IClassFactory, NDR_CREATEINSTANCE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(CreateInstance, r);		
	}

	*ppv = r.out.ppv;

	return r.out.result;
}


static WERROR dcom_proxy_IClassFactory_RemoteCreateInstance(struct IClassFactory *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemoteCreateInstance r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemoteCreateInstance, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IClassFactory, NDR_REMOTECREATEINSTANCE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemoteCreateInstance, r);		
	}


	return r.out.result;
}


static WERROR dcom_proxy_IClassFactory_LockServer(struct IClassFactory *d, TALLOC_CTX *mem_ctx, uint8_t lock)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct LockServer r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.lock = lock;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(LockServer, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IClassFactory, NDR_LOCKSERVER, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(LockServer, r);		
	}


	return r.out.result;
}


static WERROR dcom_proxy_IClassFactory_RemoteLockServer(struct IClassFactory *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemoteLockServer r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemoteLockServer, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IClassFactory, NDR_REMOTELOCKSERVER, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemoteLockServer, r);		
	}


	return r.out.result;
}

static NTSTATUS dcom_proxy_IClassFactory_init(TALLOC_CTX *ctx)
{
	struct IClassFactory_vtable *proxy_vtable = talloc(ctx, struct IClassFactory_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->CreateInstance = dcom_proxy_IClassFactory_CreateInstance;
	proxy_vtable->RemoteCreateInstance = dcom_proxy_IClassFactory_RemoteCreateInstance;
	proxy_vtable->LockServer = dcom_proxy_IClassFactory_LockServer;
	proxy_vtable->RemoteLockServer = dcom_proxy_IClassFactory_RemoteLockServer;

	proxy_vtable->iid = ndr_table_IClassFactory.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IRemUnknown generated by pidl */


static WERROR dcom_proxy_IRemUnknown_RemQueryInterface(struct IRemUnknown *d, TALLOC_CTX *mem_ctx, struct GUID *ripid, uint32_t cRefs, uint16_t cIids, struct GUID *iids, struct MInterfacePointer *ip)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemQueryInterface r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.ripid = ripid;
	r.in.cRefs = cRefs;
	r.in.cIids = cIids;
	r.in.iids = iids;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemQueryInterface, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IRemUnknown, NDR_REMQUERYINTERFACE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemQueryInterface, r);		
	}

	*ip = r.out.ip;

	return r.out.result;
}


static WERROR dcom_proxy_IRemUnknown_RemAddRef(struct IRemUnknown *d, TALLOC_CTX *mem_ctx, uint16_t cInterfaceRefs, struct REMINTERFACEREF *InterfaceRefs, WERROR *pResults)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemAddRef r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.cInterfaceRefs = cInterfaceRefs;
	r.in.InterfaceRefs = InterfaceRefs;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemAddRef, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IRemUnknown, NDR_REMADDREF, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemAddRef, r);		
	}

	*pResults = r.out.pResults;

	return r.out.result;
}


static WERROR dcom_proxy_IRemUnknown_RemRelease(struct IRemUnknown *d, TALLOC_CTX *mem_ctx, uint16_t cInterfaceRefs, struct REMINTERFACEREF *InterfaceRefs)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemRelease r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.cInterfaceRefs = cInterfaceRefs;
	r.in.InterfaceRefs = InterfaceRefs;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemRelease, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IRemUnknown, NDR_REMRELEASE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemRelease, r);		
	}


	return r.out.result;
}

static NTSTATUS dcom_proxy_IRemUnknown_init(TALLOC_CTX *ctx)
{
	struct IRemUnknown_vtable *proxy_vtable = talloc(ctx, struct IRemUnknown_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->RemQueryInterface = dcom_proxy_IRemUnknown_RemQueryInterface;
	proxy_vtable->RemAddRef = dcom_proxy_IRemUnknown_RemAddRef;
	proxy_vtable->RemRelease = dcom_proxy_IRemUnknown_RemRelease;

	proxy_vtable->iid = ndr_table_IRemUnknown.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IClassActivator generated by pidl */


static void dcom_proxy_IClassActivator_GetClassObject(struct IClassActivator *d, TALLOC_CTX *mem_ctx, struct GUID clsid, uint32_t context, uint32_t locale, struct GUID iid, struct MInterfacePointer *data)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct GetClassObject r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.clsid = clsid;
	r.in.context = context;
	r.in.locale = locale;
	r.in.iid = iid;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(GetClassObject, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IClassActivator, NDR_GETCLASSOBJECT, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(GetClassObject, r);		
	}

	*data = r.out.data;

	return r.out.result;
}

static NTSTATUS dcom_proxy_IClassActivator_init(TALLOC_CTX *ctx)
{
	struct IClassActivator_vtable *proxy_vtable = talloc(ctx, struct IClassActivator_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->GetClassObject = dcom_proxy_IClassActivator_GetClassObject;

	proxy_vtable->iid = ndr_table_IClassActivator.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for ISCMLocalActivator generated by pidl */


static WERROR dcom_proxy_ISCMLocalActivator_ISCMLocalActivator_CreateInstance(struct ISCMLocalActivator *d, TALLOC_CTX *mem_ctx)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct ISCMLocalActivator_CreateInstance r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(ISCMLocalActivator_CreateInstance, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_ISCMLocalActivator, NDR_ISCMLOCALACTIVATOR_CREATEINSTANCE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(ISCMLocalActivator_CreateInstance, r);		
	}


	return r.out.result;
}

static NTSTATUS dcom_proxy_ISCMLocalActivator_init(TALLOC_CTX *ctx)
{
	struct ISCMLocalActivator_vtable *proxy_vtable = talloc(ctx, struct ISCMLocalActivator_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IClassActivator.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IClassActivator'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IClassActivator_vtable));

	proxy_vtable->ISCMLocalActivator_CreateInstance = dcom_proxy_ISCMLocalActivator_ISCMLocalActivator_CreateInstance;

	proxy_vtable->iid = ndr_table_ISCMLocalActivator.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for ISystemActivator generated by pidl */


static WERROR dcom_proxy_ISystemActivator_ISystemActivatorRemoteCreateInstance(struct ISystemActivator *d, TALLOC_CTX *mem_ctx, uint64_t unknown1, struct MInterfacePointer iface1, uint64_t unknown2, uint32_t *unknown3, struct MInterfacePointer *iface2)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct ISystemActivatorRemoteCreateInstance r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.unknown1 = unknown1;
	r.in.iface1 = iface1;
	r.in.unknown2 = unknown2;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(ISystemActivatorRemoteCreateInstance, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_ISystemActivator, NDR_ISYSTEMACTIVATORREMOTECREATEINSTANCE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(ISystemActivatorRemoteCreateInstance, r);		
	}

	*unknown3 = r.out.unknown3;
	*iface2 = r.out.iface2;

	return r.out.result;
}

static NTSTATUS dcom_proxy_ISystemActivator_init(TALLOC_CTX *ctx)
{
	struct ISystemActivator_vtable *proxy_vtable = talloc(ctx, struct ISystemActivator_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IClassActivator.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IClassActivator'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IClassActivator_vtable));

	proxy_vtable->ISystemActivatorRemoteCreateInstance = dcom_proxy_ISystemActivator_ISystemActivatorRemoteCreateInstance;

	proxy_vtable->iid = ndr_table_ISystemActivator.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IRemUnknown2 generated by pidl */


static WERROR dcom_proxy_IRemUnknown2_RemQueryInterface2(struct IRemUnknown2 *d, TALLOC_CTX *mem_ctx, struct GUID *ripid, uint16_t cIids, struct GUID *iids, WERROR *phr, struct MInterfacePointer *ppMIF)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct RemQueryInterface2 r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.ripid = ripid;
	r.in.cIids = cIids;
	r.in.iids = iids;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(RemQueryInterface2, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IRemUnknown2, NDR_REMQUERYINTERFACE2, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(RemQueryInterface2, r);		
	}

	*phr = r.out.phr;
	*ppMIF = r.out.ppMIF;

	return r.out.result;
}

static NTSTATUS dcom_proxy_IRemUnknown2_init(TALLOC_CTX *ctx)
{
	struct IRemUnknown2_vtable *proxy_vtable = talloc(ctx, struct IRemUnknown2_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IRemUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IRemUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IRemUnknown_vtable));

	proxy_vtable->RemQueryInterface2 = dcom_proxy_IRemUnknown2_RemQueryInterface2;

	proxy_vtable->iid = ndr_table_IRemUnknown2.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IDispatch generated by pidl */


static WERROR dcom_proxy_IDispatch_GetTypeInfoCount(struct IDispatch *d, TALLOC_CTX *mem_ctx, uint16_t *pctinfo)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct GetTypeInfoCount r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(GetTypeInfoCount, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IDispatch, NDR_GETTYPEINFOCOUNT, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(GetTypeInfoCount, r);		
	}

	*pctinfo = r.out.pctinfo;

	return r.out.result;
}


static WERROR dcom_proxy_IDispatch_GetTypeInfo(struct IDispatch *d, TALLOC_CTX *mem_ctx, uint16_t iTInfo, uint32_t lcid, struct REF_ITypeInfo *ppTInfo)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct GetTypeInfo r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.iTInfo = iTInfo;
	r.in.lcid = lcid;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(GetTypeInfo, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IDispatch, NDR_GETTYPEINFO, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(GetTypeInfo, r);		
	}

	*ppTInfo = r.out.ppTInfo;

	return r.out.result;
}


static WERROR dcom_proxy_IDispatch_GetIDsOfNames(struct IDispatch *d, TALLOC_CTX *mem_ctx, struct GUID *riid, uint16_t cNames, uint32_t lcid, uint32_t *rgDispId)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct GetIDsOfNames r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.riid = riid;
	r.in.cNames = cNames;
	r.in.lcid = lcid;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(GetIDsOfNames, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IDispatch, NDR_GETIDSOFNAMES, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(GetIDsOfNames, r);		
	}

	*rgDispId = r.out.rgDispId;

	return r.out.result;
}


static WERROR dcom_proxy_IDispatch_Invoke(struct IDispatch *d, TALLOC_CTX *mem_ctx, uint32_t dispIdMember, struct GUID *riid, uint32_t lcid, uint16_t wFlags, struct DISPPARAMS *pDispParams, struct VARIANT *pVarResult, struct EXCEPINFO *pExcepInfo, uint16_t *puArgErr)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct Invoke r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.dispIdMember = dispIdMember;
	r.in.riid = riid;
	r.in.lcid = lcid;
	r.in.wFlags = wFlags;
	r.in.pDispParams = pDispParams;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(Invoke, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IDispatch, NDR_INVOKE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(Invoke, r);		
	}

	*pDispParams = r.out.pDispParams;
	*pVarResult = r.out.pVarResult;
	*pExcepInfo = r.out.pExcepInfo;
	*puArgErr = r.out.puArgErr;

	return r.out.result;
}

static NTSTATUS dcom_proxy_IDispatch_init(TALLOC_CTX *ctx)
{
	struct IDispatch_vtable *proxy_vtable = talloc(ctx, struct IDispatch_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->GetTypeInfoCount = dcom_proxy_IDispatch_GetTypeInfoCount;
	proxy_vtable->GetTypeInfo = dcom_proxy_IDispatch_GetTypeInfo;
	proxy_vtable->GetIDsOfNames = dcom_proxy_IDispatch_GetIDsOfNames;
	proxy_vtable->Invoke = dcom_proxy_IDispatch_Invoke;

	proxy_vtable->iid = ndr_table_IDispatch.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for ICoffeeMachine generated by pidl */


static WERROR dcom_proxy_ICoffeeMachine_MakeCoffee(struct ICoffeeMachine *d, TALLOC_CTX *mem_ctx, uint16_t *flavor)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct MakeCoffee r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.flavor = flavor;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(MakeCoffee, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_ICoffeeMachine, NDR_MAKECOFFEE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(MakeCoffee, r);		
	}


	return r.out.result;
}

static NTSTATUS dcom_proxy_ICoffeeMachine_init(TALLOC_CTX *ctx)
{
	struct ICoffeeMachine_vtable *proxy_vtable = talloc(ctx, struct ICoffeeMachine_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->MakeCoffee = dcom_proxy_ICoffeeMachine_MakeCoffee;

	proxy_vtable->iid = ndr_table_ICoffeeMachine.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

/* DCOM proxy for IStream generated by pidl */


static WERROR dcom_proxy_IStream_Read(struct IStream *d, TALLOC_CTX *mem_ctx, uint8_t *pv, uint32_t num_requested, uint32_t *num_readx, uint32_t *num_read)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct Read r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.num_requested = num_requested;
	r.in.num_readx = num_readx;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(Read, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IStream, NDR_READ, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(Read, r);		
	}

	*pv = r.out.pv;
	*num_read = r.out.num_read;

	return r.out.result;
}


static WERROR dcom_proxy_IStream_Write(struct IStream *d, TALLOC_CTX *mem_ctx, uint8_t *data, uint32_t num_requested, uint32_t *num_written)
{
	struct dcerpc_pipe *p;
	NTSTATUS status = dcom_get_pipe(d, &p);
	struct Write r;
	struct rpc_request *req;

	if (NT_STATUS_IS_ERR(status)) {
		return status;
	}

	ZERO_STRUCT(r.in.ORPCthis);
	r.in.ORPCthis.version.MajorVersion = COM_MAJOR_VERSION;
	r.in.ORPCthis.version.MinorVersion = COM_MINOR_VERSION;
	r.in.data = data;
	r.in.num_requested = num_requested;

	if (p->conn->flags & DCERPC_DEBUG_PRINT_IN) {
		NDR_PRINT_IN_DEBUG(Write, &r);		
	}

	status = dcerpc_ndr_request(p, &d->ipid, &ndr_table_IStream, NDR_WRITE, mem_ctx, &r);

	if (NT_STATUS_IS_OK(status) && (p->conn->flags & DCERPC_DEBUG_PRINT_OUT)) {
		NDR_PRINT_OUT_DEBUG(Write, r);		
	}

	*num_written = r.out.num_written;

	return r.out.result;
}

static NTSTATUS dcom_proxy_IStream_init(TALLOC_CTX *ctx)
{
	struct IStream_vtable *proxy_vtable = talloc(ctx, struct IStream_vtable);

	struct GUID base_iid;
	const void *base_vtable;

	base_iid = ndr_table_IUnknown.syntax_id.uuid;

	base_vtable = dcom_proxy_vtable_by_iid(&base_iid);
	if (base_vtable == NULL) {
		DEBUG(0, ("No proxy registered for base interface 'IUnknown'\n"));
		return NT_STATUS_FOOBAR;
	}
	
	memcpy(&proxy_vtable, base_vtable, sizeof(struct IUnknown_vtable));

	proxy_vtable->Read = dcom_proxy_IStream_Read;
	proxy_vtable->Write = dcom_proxy_IStream_Write;

	proxy_vtable->iid = ndr_table_IStream.syntax_id.uuid;

	return dcom_register_proxy(ctx, (struct IUnknown_vtable *)proxy_vtable);
}

