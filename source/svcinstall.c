/*
  Copyright (C) Andrzej Hajda 2009-2013
  Contact: andrzej.hajda@wp.pl
  License: GNU General Public License version 3
*/
#include <stdint.h>
#include <core/ntstatus.h>
#include <fcntl.h>

#include <tevent.h>
#include <credentials.h>
#include <util/time.h>
#include <gen_ndr/ndr_svcctl_c.h>
// #include "libcli/raw/libcliraw.h"
#include "libcli/libcli.h"
#include "smb_cliraw.h"
#include "libcli/smb_composite/smb_composite.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "debug.h"

#include "winexesvc.h"
#include "svcinstall.h"

//#define SERVICE_ALL_ACCESS (0xF01FF)
#define SERVICE_NO_CHANGE (0xffffffff)
#define SERVICE_INTERACTIVE_PROCESS (0x00000100)

#define SERVICE_STATE_ACTIVE (0x01)
#define SERVICE_STATE_INACTIVE (0x02)
#define SERVICE_STATE_ALL (0x03)
#define SERVICE_WIN32_OWN_PROCESS (0x00000010)
#define SERVICE_DEMAND_START (0x00000003)
#define SERVICE_ERROR_NORMAL (0x00000001)
#define SERVICE_CONTROL_STOP (0x00000001)
#define NT_STATUS_SERVICE_DOES_NOT_EXIST NT_STATUS(0xc0000424)

#define NT_ERR(status, lvl, args...) if (!NT_STATUS_IS_OK(status)) { DEBUG(lvl,("ERROR: " args)); DEBUG(lvl,(". %s.\n", nt_errstr(status))); return status; }
#define NT_RES(status, werr) (NT_STATUS_IS_OK(status) ? werror_to_ntstatus(werr) : status)

static NTSTATUS svc_pipe_connect(struct tevent_context *ev_ctx, 
                                 struct dcerpc_pipe **psvc_pipe,
                                 const char *hostname,
                                 struct cli_credentials *credentials,
                                 struct loadparm_context *ldprm_ctx)
{
	NTSTATUS status;
	char *binding;

	if (asprintf(&binding, "ncacn_np:%s%s", hostname, DEBUGLVL(9)?"[print]":"") == -1) {
		DEBUG(0, ("ERROR: Failed trying to format a string"));
		return NT_STATUS_UNSUCCESSFUL;
	}
	status = dcerpc_pipe_connect(ev_ctx, psvc_pipe, binding,
	                             &ndr_table_svcctl, credentials, ev_ctx, ldprm_ctx);
	free(binding);
	return status;
}

static NTSTATUS svc_OpenSCManager(struct dcerpc_binding_handle *binding_handle,
                                  const char *hostname,
                                  struct policy_handle * pscm_handle)
{
	NTSTATUS status;
	struct svcctl_OpenSCManagerW r;

	r.in.MachineName = hostname;
	r.in.DatabaseName = NULL;
	r.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	r.out.handle = pscm_handle;
	status = dcerpc_svcctl_OpenSCManagerW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_OpenService(struct dcerpc_binding_handle *binding_handle,
                                struct policy_handle * pscm_handle,
                                const char *ServiceName,
                                struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_OpenServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.access_mask = SERVICE_ALL_ACCESS;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_OpenServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_CreateService(struct dcerpc_binding_handle *binding_handle,
                                  struct policy_handle * pscm_handle,
                                  const char *ServiceName,
                                  uint32_t type,
                                  const char *binary_path,
                                  struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CreateServiceW r;

	r.in.scmanager_handle = pscm_handle;
	r.in.ServiceName = ServiceName;
	r.in.DisplayName = NULL;
	r.in.desired_access = SERVICE_ALL_ACCESS;
	r.in.type = type;
	r.in.start_type = SERVICE_DEMAND_START;
	r.in.error_control = SERVICE_ERROR_NORMAL;
	r.in.binary_path = binary_path;
	r.in.LoadOrderGroupKey = NULL;
	r.in.TagId = NULL;
	r.in.dependencies = NULL;
	r.in.dependencies_size = 0;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.password_size = 0;
	r.out.handle = psvc_handle;
	r.out.TagId = NULL;
	status = dcerpc_svcctl_CreateServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_ChangeServiceConfig(struct dcerpc_binding_handle *binding_handle,
                                        struct policy_handle * psvc_handle,
                                        uint32_t type,
                                        const char *binary_path)
{
	NTSTATUS status;
	struct svcctl_ChangeServiceConfigW r;

	r.in.handle = psvc_handle;
	r.in.type = type;
	r.in.start_type = SERVICE_NO_CHANGE;
	r.in.error_control = SERVICE_NO_CHANGE;
	r.in.binary_path = binary_path;
	r.in.load_order_group = NULL;
	r.in.dependencies = NULL;
	r.in.service_start_name = NULL;
	r.in.password = NULL;
	r.in.display_name = NULL;
	r.out.tag_id = NULL;
	status = dcerpc_svcctl_ChangeServiceConfigW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_StartService(struct dcerpc_binding_handle *binding_handle,
                                 struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_StartServiceW r;

	r.in.handle = psvc_handle;
	r.in.NumArgs = 0;
	r.in.Arguments = NULL;
	status = dcerpc_svcctl_StartServiceW_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_ControlService(struct dcerpc_binding_handle *binding_handle,
                                   struct policy_handle * psvc_handle,
                                   int control, struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_ControlService r;

	r.in.handle = psvc_handle;
	r.in.control = control;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_ControlService_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_QueryServiceStatus(struct dcerpc_binding_handle *binding_handle,
                                       struct policy_handle * psvc_handle,
                                       struct SERVICE_STATUS * sstatus)
{
	NTSTATUS status;
	struct svcctl_QueryServiceStatus r;

	r.in.handle = psvc_handle;
	r.out.service_status = sstatus;
	status = dcerpc_svcctl_QueryServiceStatus_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_DeleteService(struct dcerpc_binding_handle *binding_handle,
                                  struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_DeleteService r;

	r.in.handle = psvc_handle;
	status = dcerpc_svcctl_DeleteService_r(binding_handle, NULL, &r);
	return NT_RES(status, r.out.result);
}

static NTSTATUS svc_CloseServiceHandle(struct dcerpc_binding_handle *binding_handle,
				struct policy_handle * psvc_handle)
{
	NTSTATUS status;
	struct svcctl_CloseServiceHandle r;

	r.in.handle = psvc_handle;
	r.out.handle = psvc_handle;
	status = dcerpc_svcctl_CloseServiceHandle_r(binding_handle, NULL, &r);
	return status;
}

/*
  return a handle to the root of the share
*/
static NTSTATUS smb2_util_roothandle(struct smb2_tree *tree, struct smb2_handle *handle)
{
        struct smb2_create io;
        NTSTATUS status;

        ZERO_STRUCT(io);
        io.in.oplock_level = 0;
        io.in.desired_access = SEC_STD_SYNCHRONIZE | SEC_DIR_READ_ATTRIBUTE | SEC_DIR_LIST;
        io.in.file_attributes   = 0;
        io.in.create_disposition = NTCREATEX_DISP_OPEN;
        io.in.share_access = NTCREATEX_SHARE_ACCESS_READ|NTCREATEX_SHARE_ACCESS_DELETE;
        io.in.create_options = NTCREATEX_OPTIONS_ASYNC_ALERT;
        io.in.fname = "";

        status = smb2_create(tree, tree, &io);
        NT_STATUS_NOT_OK_RETURN(status);

        *handle = io.out.file.handle;

        return NT_STATUS_OK;
}

static NTSTATUS svc_UploadService(struct tevent_context *ev_ctx, 
                                  const char *hostname,
                                  const char *service_filename,
                                  unsigned char *svc32_exe, unsigned int svc32_exe_len,
                                  unsigned char *svc64_exe, unsigned int svc64_exe_len,
                                  struct cli_credentials *credentials,
                                  struct loadparm_context *ldprm_ctx,
                                  int flags)
{
        struct smb2_tree *smb2tree;
	NTSTATUS status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;
        struct smb2_handle rootHandle;
	lpcfg_smbcli_options(ldprm_ctx, &options);
	lpcfg_smbcli_session_options(ldprm_ctx, &session_options);



        status = smb2_connect(NULL, hostname, lpcfg_smb_ports(ldprm_ctx), 
                              "ADMIN$",  lpcfg_resolve_context(ldprm_ctx), credentials, 
                              &smb2tree, ev_ctx, &options, lpcfg_socket_options(ldprm_ctx),
                               lpcfg_gensec_settings(NULL, ldprm_ctx));

	NT_ERR(status, 0, "Failed to open ADMIN$ share");

        status = smb2_util_roothandle(smb2tree, &rootHandle);
	NT_ERR(status, 0, "Failed to open ADMIN$ share");

	if (flags & SVC_FORCE_UPLOAD) 
        {
                smb2_util_unlink(smb2tree, service_filename);
	} 
        else 
        {
            struct smb2_create io;
            ZERO_STRUCT(io);

            io.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
            io.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
            io.in.create_disposition = NTCREATEX_DISP_OPEN;
            io.in.share_access =
                NTCREATEX_SHARE_ACCESS_DELETE|
                NTCREATEX_SHARE_ACCESS_READ|
                NTCREATEX_SHARE_ACCESS_WRITE;
            io.in.create_options = 0;
            io.in.fname = service_filename;

            status = smb2_create(smb2tree, smb2tree, &io);
            if (NT_STATUS_IS_OK(status))
            { 
                struct smb2_close c;
                ZERO_STRUCT(c);

                c.in.file.handle       = io.out.file.handle;
                c.in.flags           = SMB2_CLOSE_FLAGS_FULL_INFORMATION;

                status = smb2_close(smb2tree, &c);

                return status;
            } 
	}
	if (flags & SVC_OSCHOOSE)
        {

            struct smb2_find io;
            ZERO_STRUCT(io);
            TALLOC_CTX *tmp_ctx = talloc_new(smb2tree);

            io.in.file.handle = rootHandle;
            io.in.max_response_size  = 0x1000;
            io.in.continue_flags = SMB2_CONTINUE_FLAG_SINGLE;
            io.in.level = SMB2_FIND_DIRECTORY_INFO;
            io.in.pattern = "SysWoW64";

            status = smb2_find(smb2tree, tmp_ctx, &io);
            talloc_free(tmp_ctx);
        }
        struct smb2_create cr;
        ZERO_STRUCT(cr);

        cr.in.desired_access = SEC_FLAG_MAXIMUM_ALLOWED;
        cr.in.file_attributes   = FILE_ATTRIBUTE_NORMAL;
        cr.in.create_disposition = NTCREATEX_DISP_OPEN_IF;
        cr.in.share_access =
            NTCREATEX_SHARE_ACCESS_DELETE|
            NTCREATEX_SHARE_ACCESS_READ|
            NTCREATEX_SHARE_ACCESS_WRITE;
        cr.in.create_options = 0;
        cr.in.fname = service_filename;
        TALLOC_CTX *tmp_ctx = talloc_new(smb2tree);
        status = smb2_create(smb2tree, tmp_ctx, &cr);
	NT_ERR(status, 0, "Failed to create ADMIN$/%s", service_filename);
        struct smb2_write w;
        ZERO_STRUCT(w);
        w.in.file.handle = cr.out.file.handle;
        w.in.offset      = 0;

	if (((flags & SVC_OSCHOOSE) && NT_STATUS_IS_OK(status)) || (flags & SVC_OS64BIT)) {
		DEBUG(1, ("svc_UploadService: Installing 64bit %s\n", service_filename));
                w.in.data = data_blob_const(svc64_exe,svc64_exe_len);

	} else {
		DEBUG(1, ("svc_UploadService: Installing 32bit %s\n", service_filename));
                w.in.data = data_blob_const(svc32_exe,svc32_exe_len);

	}
        status = smb2_write(smb2tree, &w);
        if (NT_STATUS_IS_OK(status)) {
        }
	NT_ERR(status, 0, "Failed to save ADMIN$/%s", service_filename);
        struct smb2_close c;
        ZERO_STRUCT(c);

        c.in.file.handle     =  cr.out.file.handle;
        c.in.flags           = SMB2_CLOSE_FLAGS_FULL_INFORMATION;

        status = smb2_close(smb2tree, &c);

	return status;
}

/* Start, Creates, Install service if necessary */
NTSTATUS svc_install(struct tevent_context *ev_ctx, 
                     const char *hostname,
                     const char *service_name, const char *service_filename,
                     unsigned char *svc32_exe, unsigned int svc32_exe_len,
                     unsigned char *svc64_exe, unsigned int svc64_exe_len,
                     struct cli_credentials *credentials,
                     struct loadparm_context *ldprm_ctx,
                     int flags)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *binding_handle;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	struct SERVICE_STATUS s;
	int need_start = 0;
	int need_conf = 0;

	status = svc_pipe_connect(ev_ctx, &svc_pipe, hostname, credentials, ldprm_ctx);
	NT_ERR(status, 0, "Cannot connect to svcctl pipe");
	binding_handle = svc_pipe->binding_handle;
	status = svc_OpenSCManager(binding_handle, hostname, &scm_handle);
	NT_ERR(status, 0, "OpenSCManager failed");

	status = svc_OpenService(binding_handle, &scm_handle, service_name, &svc_handle);
	if (NT_STATUS_EQUAL(status, NT_STATUS_SERVICE_DOES_NOT_EXIST)) {
		status = svc_CreateService(binding_handle, &scm_handle, service_name,
		                           SERVICE_WIN32_OWN_PROCESS | 
		                           ((flags & SVC_INTERACTIVE) ? SERVICE_INTERACTIVE_PROCESS : 0),
		                           service_filename, &svc_handle);
		NT_ERR(status, 0, "CreateService failed");
		need_start = 1;
	} else {
		NT_ERR(status, 0, "OpenService failed");
	}

	status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
	NT_ERR(status, 0, "QueryServiceStatus failed");

	if (!(flags & SVC_IGNORE_INTERACTIVE))
		need_conf = !(s.type & SERVICE_INTERACTIVE_PROCESS) ^ !(flags & SVC_INTERACTIVE);

	if (s.state == SVCCTL_STOPPED) {
		need_start = 1;
	} else if (need_conf) {
		status = svc_ControlService(binding_handle, &svc_handle,
		                            SERVICE_CONTROL_STOP, &s);
		NT_ERR(status, 0, "StopService failed");
		do {
			smb_msleep(100);
			status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
			NT_ERR(status, 0, "QueryServiceStatus failed");
		} while (s.state == SVCCTL_STOP_PENDING);
		need_start = 1;
	}

	if (need_conf) {
		status = svc_ChangeServiceConfig(binding_handle, &svc_handle,
		                                 SERVICE_WIN32_OWN_PROCESS |
		                                 ((flags & SVC_INTERACTIVE) ? SERVICE_INTERACTIVE_PROCESS : 0),
		                                 NULL);
		NT_ERR(status, 0, "ChangeServiceConfig failed");
	}

	if (need_start) {
		status = svc_UploadService(ev_ctx, hostname, service_filename,
		                           svc32_exe, svc32_exe_len,
		                           svc64_exe, svc64_exe_len,
		                           credentials, ldprm_ctx, flags);
		NT_ERR(status, 0, "UploadService failed");

		status = svc_StartService(binding_handle, &svc_handle);
		NT_ERR(status, 0, "StartService failed");
		do {
			smb_msleep(100);
			status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
			NT_ERR(status, 0, "QueryServiceStatus failed");
		} while (s.state == SVCCTL_START_PENDING);
		if (s.state != SVCCTL_RUNNING) {
			DEBUG(0, ("Service cannot start, status=0x%08X\n", s.state));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	svc_CloseServiceHandle(binding_handle, &svc_handle);
	svc_CloseServiceHandle(binding_handle, &scm_handle);
	talloc_free(svc_pipe);
	return status;
}

NTSTATUS svc_uninstall(struct tevent_context *ev_ctx,
                       const char *hostname,
                       const char *service_name, const char *service_filename,
                       struct cli_credentials *credentials,
                       struct loadparm_context *ldprm_ctx)
{
	NTSTATUS status;
	struct dcerpc_binding_handle *binding_handle;
	struct dcerpc_pipe *svc_pipe;
	struct policy_handle scm_handle;
	struct policy_handle svc_handle;
	struct SERVICE_STATUS svc_status;
	struct smbcli_options options;
	struct smbcli_session_options session_options;

	lpcfg_smbcli_options(ldprm_ctx, &options);
	lpcfg_smbcli_session_options(ldprm_ctx, &session_options);

	status = svc_pipe_connect(ev_ctx, &svc_pipe, hostname, credentials, ldprm_ctx);
	NT_ERR(status, 1, "Cannot connect to svcctl pipe");
	binding_handle = svc_pipe->binding_handle;
	status = svc_OpenSCManager(binding_handle, hostname, &scm_handle);
	NT_ERR(status, 1, "OpenSCManager failed");
	status = svc_OpenService(binding_handle, &scm_handle, service_name,
	                         &svc_handle);
	NT_ERR(status, 1, "OpenService failed");
	DEBUG(1, ("OpenService - %s\n", nt_errstr(status)));
	if (NT_STATUS_IS_OK(status)) {
		status = svc_ControlService(binding_handle, &svc_handle,
		                            SERVICE_CONTROL_STOP, &svc_status);
		{
			struct SERVICE_STATUS s;
			do {
				smb_msleep(100);
				status = svc_QueryServiceStatus(binding_handle, &svc_handle, &s);
				NT_ERR(status, 1, "QueryServiceStatus failed");
			} while (s.state == SVCCTL_STOP_PENDING);
			if (s.state != SVCCTL_STOPPED) {
				DEBUG(0, ("Service cannot stop, status=0x%08X\n", s.state));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}
		DEBUG(1, ("StopService - %s\n", nt_errstr(status)));
		status = svc_DeleteService(binding_handle, &svc_handle);
		DEBUG(1, ("DeleteService - %s\n", nt_errstr(status)));
		status = svc_CloseServiceHandle(binding_handle, &svc_handle);
		DEBUG(1, ("CloseServiceHandle - %s\n", nt_errstr(status)));
	}
	svc_CloseServiceHandle(binding_handle, &scm_handle);
	DEBUG(1, ("CloseSCMHandle - %s\n", nt_errstr(status)));

	struct smbcli_state *cli;
	status = smbcli_full_connection(NULL, &cli, hostname, lpcfg_smb_ports(ldprm_ctx),
	                                "ADMIN$", NULL,
	                                lpcfg_socket_options(ldprm_ctx), credentials,
	                                lpcfg_resolve_context(ldprm_ctx), ev_ctx,
	                                &options, &session_options,
	                                lpcfg_gensec_settings(NULL, ldprm_ctx));
	NT_ERR(status, 1, "Failed to open ADMIN$ share");
	/* Give svc some time to exit */
	smb_msleep(300);
	status = smbcli_unlink(cli->tree, service_filename);
	DEBUG(1, ("Delete %s - %s\n", service_filename, nt_errstr(status)));
	status = smbcli_tdis(cli);
	DEBUG(1, ("Closing ADMIN$ - %s\n", nt_errstr(status)));
	talloc_free(svc_pipe);
	return status;
}
