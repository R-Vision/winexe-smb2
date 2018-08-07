/*
  Copyright (C) Andrzej Hajda 2009-2013
  Contact: andrzej.hajda@wp.pl
  License: GNU General Public License version 3
*/

enum { ASYNC_OPEN, ASYNC_OPEN_RECV, ASYNC_READ, ASYNC_READ_RECV,
       ASYNC_WRITE, ASYNC_WRITE_RECV, ASYNC_CLOSE, ASYNC_CLOSE_RECV };

typedef void (*async_cb_create) (void *ctx);
typedef void (*async_cb_read) (void *ctx, const char *data, int len);
typedef void (*async_cb_write) (void *ctx);
typedef void (*async_cb_close) (void *ctx);
typedef void (*async_cb_error) (void *ctx, int func, NTSTATUS status);

struct list_item {
	struct list_item *next;
	int size;
	char data[0];
};

struct data_list {
	struct list_item *begin;
	struct list_item *end;
};

struct async_context {
/* Public - must be initialized by client */
	struct smb2_tree *tree;
	void *cb_ctx;
	async_cb_create cb_create;
	async_cb_read cb_read;
	async_cb_write cb_write;
	async_cb_close cb_close;
	async_cb_error cb_error;
/* Private - internal usage, initialize to zeros */
        struct smb2_handle io_handle;
	/* int fd; */
	struct smb2_create *io_create;
	struct smb2_read *io_read;
	struct smb2_write *io_write;
	struct smb2_close *io_close;
	struct smb2_request *rreq;
	struct smb2_request *wreq;
	struct data_list wq;
};

int async_create(struct async_context *c, const char *fn, int create_mode);
int async_write(struct async_context *c, const void *buf, int len);
int async_close(struct async_context *c);
