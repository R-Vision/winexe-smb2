/*
  Copyright (C) Andrzej Hajda 2009-2013
  Contact: andrzej.hajda@wp.pl
  License: GNU General Public License version 3
*/

#include <talloc.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <core/ntstatus.h>
#include <core/werror.h>
#include <util/data_blob.h>
#include <util/time.h>
#include "smb_cliraw.h"
#include "smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "debug.h"

#include "async.h"

static int async_read(struct async_context *c);

static void list_enqueue(struct data_list *l, const void *data, int size)
{
	struct list_item *li = talloc_size(0, sizeof(struct list_item) + size);
	memcpy(li->data, data, size);
	li->size = size;
	li->next = 0;
	if (l->end)
		l->end->next = li;
	else
		l->begin = li;
	l->end = li;
}

static void list_dequeue(struct data_list *l)
{
	struct list_item *li = l->begin;
	if (!li)
		return;
	l->begin = li->next;
	if (!l->begin)
		l->end = 0;
	talloc_free(li);
}

static void async_read_recv(struct smb2_request *req)
{
	struct async_context *c = req->async.private_data;
	NTSTATUS status;

	status = smb2_read_recv(req, NULL,c->io_read);
	c->rreq = NULL;
	if (!NT_STATUS_IS_OK(status)) {

		DEBUG(1, ("ERROR: smb2_read_recv - %s\n", nt_errstr(status)));
		if (c->cb_error)
			c->cb_error(c->cb_ctx, ASYNC_READ_RECV, status);
		return;
	}
        
	if (c->cb_read)
		c->cb_read(c->cb_ctx, c->io_read->out.data.data, c->io_read->out.data.length);

	async_read(c);
}

static void async_write_recv(struct smb2_request *req)
{
	struct async_context *c = req->async.private_data;
	NTSTATUS status;
	status = smb2_write_recv(req, c->io_write);
	c->wreq = NULL;
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ERROR: smb2_write_recv - %s\n", nt_errstr(status)));
		talloc_free(c->io_write);
		c->io_write = 0;
		if (c->cb_error)
			c->cb_error(c->cb_ctx, ASYNC_WRITE_RECV, status);
		return;
	}

	if (c->cb_write)
{
		c->cb_write(c->cb_ctx);
}

	if (c->wq.begin) {
		async_write(c, c->wq.begin->data, c->wq.begin->size);
		list_dequeue(&c->wq);
	}
}

static void async_create_recv(struct smb2_request *req)
{
	struct async_context *c = req->async.private_data;
	NTSTATUS status;

	DEBUG(1, ("IN: async_create_recv\n"));
	status = smb2_create_recv(req, c, c->io_create);
	c->rreq = NULL;
	if (NT_STATUS_IS_OK(status))
{
		c->io_handle = c->io_create->out.file.handle;
}
	talloc_free(c->io_create);
	c->io_create = 0;
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("ERROR: smb2_create_recv - %s\n", nt_errstr(status)));
		if (c->cb_error)
			c->cb_error(c->cb_ctx, ASYNC_OPEN_RECV, status);
		return;
	}
	if (c->cb_create)
		c->cb_create(c->cb_ctx);
	async_read(c);
}

static void async_close_recv(struct smb2_request *req)
{
	struct async_context *c = req->async.private_data;

	(void) smb2_request_receive(req);
	smb2_request_destroy(req);
	talloc_free(c->io_close);
	c->io_close = 0;
	if (c->io_create) {
		talloc_free(c->io_create);
		c->io_create = 0;
	}
	if (c->io_read) {
		talloc_free(c->io_read);
		c->io_read = 0;
	}
	if (c->io_write) {
		talloc_free(c->io_write);
		c->io_write = 0;
	}
	if (c->cb_close)
		c->cb_close(c->cb_ctx);
}

static int async_read(struct async_context *c)
{
	if (!c->io_read) {
		c->io_read = talloc(c->tree, struct smb2_read);
		c->io_read->level = RAW_READ_SMB2;
		c->io_read->in.file.handle = c->io_handle;
		c->io_read->in.offset = 0;
		c->io_read->in.min_count = 0;
		c->io_read->in.length = 256;
		c->io_read->in.remaining = 0;
		/* c->io_read->in.read_for_execute = false; */
	}
	c->rreq = smb2_read_send(c->tree, c->io_read);
	if (!c->rreq) {
		if (c->cb_error)
			c->cb_error(c->cb_ctx, ASYNC_READ, NT_STATUS_NO_MEMORY);
		return 0;
	}
	c->rreq->transport->options.request_timeout = 0;
	c->rreq->async.fn = async_read_recv;
	c->rreq->async.private_data = c;
	return 1;
}

int async_create(struct async_context *c, const char *fn, int open_mode)
{
	c->io_create = talloc_zero(c, struct smb2_create);
	if (!c->io_create)
		goto failed;
	c->io_create->level = RAW_OPEN_SMB2;
	c->io_create->in.create_flags = 0;
	/* c->io_create->in.root_fid.fnum = 0; */
	c->io_create->in.desired_access =
		SEC_STD_READ_CONTROL |
		SEC_FILE_WRITE_ATTRIBUTE |
		SEC_FILE_WRITE_EA |
		SEC_FILE_READ_DATA |
		SEC_FILE_WRITE_DATA;
	c->io_create->in.create_disposition = NTCREATEX_DISP_OPEN;
	c->io_create->in.impersonation_level    = SMB2_IMPERSONATION_IMPERSONATION;
	c->io_create->in.create_options = NTCREATEX_OPTIONS_NON_DIRECTORY_FILE | NTCREATEX_OPTIONS_WRITE_THROUGH;
	c->io_create->in.security_flags = 0;
	c->io_create->in.fname = fn;
	c->rreq = smb2_create_send(c->tree, c->io_create);
	if (!c->rreq)
		goto failed;
	c->rreq->async.fn = async_create_recv;
	c->rreq->async.private_data = c;
 	return 1;

  failed:
	DEBUG(1, ("ERROR: async_create\n"));
	talloc_free(c);
	return 0;
}

int async_write(struct async_context *c, const void *buf, int len)
{
	if (c->wreq) {
		list_enqueue(&c->wq, buf, len);
		return 0;
	}
	if (!c->io_write) {
		c->io_write = talloc_zero(c, struct smb2_write);
		if (!c->io_write)
			goto failed;
		c->io_write->level = RAW_WRITE_SMB2;
		/* c->io_write->in.remaining = 0; */
		c->io_write->in.file.handle = c->io_handle;
		c->io_write->in.offset = 0;
	}
	/* c->io_write->write.in.count = len; */
	c->io_write->in.data = data_blob_const(buf, len);

	struct smb2_request *req = smb2_write_send(c->tree, c->io_write);
	if (!req)
		goto failed;
	req->async.fn = async_write_recv;
	req->async.private_data = c;
	return 1;
  failed:
	DEBUG(1, ("ERROR: async_write\n"));
	talloc_free(c->io_write);
	c->io_write = 0;
	return 0;
}

int async_close(struct async_context *c)
{
	if (c->rreq)
		smb2_request_destroy(c->rreq);
	if (c->wreq)
		smb2_request_destroy(c->wreq);
	c->rreq = c->wreq = NULL;
	c->io_close = talloc_zero(c, struct smb2_close);
	if (!c->io_close)
		goto failed;
	c->io_close->level = RAW_CLOSE_CLOSE;
	c->io_close->in.file.handle = c->io_handle;
	/* c->io_close->in.write_time = 0; */
	struct smb2_request *req = smb2_close_send(c->tree, c->io_close);
	if (!req)
		goto failed;
	req->async.fn = async_close_recv;
	req->async.private_data = c;
	return 1;
  failed:
	DEBUG(1, ("ERROR: async_close\n"));
	talloc_free(c->io_close);
	c->io_close = 0;
	return 0;
}
