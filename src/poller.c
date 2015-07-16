/* Copyright (c) 2015, Anton Belka
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *       * Redistributions of source code must retain the above copyright
 *         notice, this list of conditions and the following disclaimer.
 *       * Redistributions in binary form must reproduce the above copyright
 *         notice, this list of conditions and the following disclaimer in the
 *         documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"
#include "utlist.h"
#include "main.h"
#include "libutil/map.h"
#include "xxhash.h"
#include <archive.h>
#include <archive_entry.h>

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

#define PATH_ARCHIVEINFO "/archiveinfo"
#define PATH_EXTRACTFILES "/extractfiles"

/* Init functions */
gpointer init_poller_worker (struct rspamd_config *cfg);
void start_poller_worker (struct rspamd_worker *worker);

worker_t poller_worker = {
	"poller",                   /* Name */
	init_poller_worker,         /* Init function */
	start_poller_worker,        /* Start function */
	TRUE,                       /* Has socket */
	FALSE,                      /* Non unique */
	FALSE,                      /* Non threaded */
	TRUE,                       /* Killable */
  SOCK_STREAM                 /* TCP socket */
};

/*
 * Worker's context
 */
struct rspamd_poller_worker_ctx {
	guint32 timeout;
	struct timeval io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* HTTP server */
	struct rspamd_http_connection_router *http;
	/* Server's start time */
	time_t start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* Configuration */
	struct rspamd_config *cfg;
	/* Worker */
	struct rspamd_worker *worker;

	/* Static files dir */
	gchar *static_files_dir;

	/* Local keypair */
	gpointer key;
};

struct rspamd_poller_session {
	struct rspamd_poller_worker_ctx *ctx;
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	rspamd_inet_addr_t *from_addr;
};

static void
rspamd_poller_error_handler (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	msg_err ("http error occurred: %s", err->message);
}

static void
rspamd_poller_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_poller_session *session = conn_ent->ud;

	session->ctx->worker->srv->stat->control_connections_count++;
	if (session->task != NULL) {
		rspamd_session_destroy (session->task->s);
	}
	if (session->pool) {
		rspamd_mempool_delete (session->pool);
	}

	rspamd_inet_address_destroy (session->from_addr);
	g_slice_free1 (sizeof (struct rspamd_poller_session), session);
}

static void
rspamd_poller_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_poller_worker_ctx *ctx;
	struct rspamd_poller_session *nsession;
	rspamd_inet_addr_t *addr;
	gint nfd;

	ctx = worker->ctx;

	if ((nfd =
		rspamd_accept_from_socket (fd, &addr)) == -1) {
		msg_warn ("accept failed: %s", strerror (errno));
		return;
	}
	/* Check for EAGAIN */
	if (nfd == 0) {
		return;
	}

	nsession = g_slice_alloc0 (sizeof (struct rspamd_poller_session));
	nsession->pool = rspamd_mempool_new (rspamd_mempool_suggest_size ());
	nsession->ctx = ctx;

	nsession->from_addr = addr;

	rspamd_http_router_handle_socket (ctx->http, nfd, nsession);
}

/*
 * Stat command handler:
 * request: /archiveinfo
 * reply: json data
 */
static int
rspamd_poller_handle_archiveinfo (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct archive *archive;
	struct archive_entry *entry;
	struct rspamd_http_header *header;
	int r;
	unsigned int errors = 0, hash = 0, offset = 0, maxsize = 0;
	size_t size = 0;
	const char *pathname = NULL;
	gchar *header_name, *header_value, *archive_name = NULL, **filter_mask = NULL;
	gboolean match_mask;
	void *buff = NULL;
	ucl_object_t *top, *sub, *obj;

	top = ucl_object_typed_new (UCL_ARRAY);
	sub = ucl_object_typed_new (UCL_ARRAY);

	archive = archive_read_new ();
	archive_read_support_filter_all (archive);
	archive_read_support_format_all (archive);

	r = archive_read_open_memory (archive, msg->body->str, msg->body->len);

	if (r != ARCHIVE_OK) {
		msg_err ("Invalid archive");
		rspamd_controller_send_error (conn_ent, 500, "Invalid archive");
	}

	header = msg->headers;
	while (header) {
		header_name = g_strndup (header->name->str, header->name->len);
		header_value = g_strndup (header->value->str, header->value->len);

		if (g_strcmp0 (header_name, "X-ARCHIVE-NAME") == 0) {
			archive_name = header_value;
		} else if (g_strcmp0 (header_name, "X-MAXFILE-SIZE") == 0) {
			maxsize = g_ascii_strtoll (header_value, NULL, 10);
		} else if (g_strcmp0 (header_name, "X-FILTER-MASK") == 0) {
			filter_mask = g_strsplit_set (header_value, " ,", -1);
		}
		header = header->next;
	}

	r = archive_read_next_header (archive, &entry);
	while (r != ARCHIVE_EOF) {
		switch (r) {
			case ARCHIVE_OK: {
				offset += size;
				size = archive_entry_size (entry);
				pathname = archive_entry_pathname (entry);

				for (guint i = 0; i < g_strv_length (filter_mask); i++) {
					if (match_mask == FALSE) {
						match_mask = g_pattern_match_simple (filter_mask[i], pathname);
					} else {
						break;
					}
				}

				if (match_mask == FALSE || (maxsize > 0 && size > maxsize)) {
					r = archive_read_next_header (archive, &entry);
				} else {
					buff = g_malloc0 (size);
					r = archive_read_data (archive, buff, size);
				}
			} break;
			case ARCHIVE_WARN:
			case ARCHIVE_FAILED:
			case ARCHIVE_FATAL: {
				errors++;
				msg_err (archive_error_string (archive));
				r = archive_read_next_header (archive, &entry);
			} break;
			default: {
				hash = XXH32 (buff, size, 0);

				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj, ucl_object_fromstring (pathname), "pathname", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromint (size), "size", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromint (hash), "hash", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromint (offset), "offset", 0, false);
				ucl_array_append (sub, obj);

				r = archive_read_next_header (archive, &entry);

				if (buff) {
					g_free (buff);
				}
			} break;
		}
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	ucl_object_insert_key (obj, ucl_object_fromint (errors), "errors", 0, false);
	ucl_array_append (top, obj);

	if (archive_name) {
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (archive_name), "name", 0, false);
		ucl_array_append (top, obj);
	}

	if (ucl_array_head (sub)) {
		ucl_array_append (top, sub);
	}

	rspamd_controller_send_ucl (conn_ent, top);

	ucl_object_unref (top);
	archive_read_free (archive);

	return 0;
}

/*
 * Stat command handler:
 * request: /extractfiles
 * reply: json data
 */
static int
rspamd_poller_handle_extractfiles (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct archive *archive;
	struct archive_entry *entry;
	int r;
	unsigned int hash;
	size_t size;
	const char *pathname = NULL;
	void *buff;
	ucl_object_t *top, *obj;

	top = ucl_object_typed_new (UCL_ARRAY);

	archive = archive_read_new ();
	archive_read_support_filter_all (archive);
	archive_read_support_format_all (archive);

	r = archive_read_open_memory (archive, msg->body->str, msg->body->len);

	if (r != ARCHIVE_OK) {
		msg_err ("Invalid archive");
		rspamd_controller_send_error (conn_ent, 500, "Invalid archive");
	}

	while (archive_read_next_header (archive, &entry) == ARCHIVE_OK) {
		size = archive_entry_size (entry);
		pathname = archive_entry_pathname (entry);
		buff = malloc (size);
		archive_read_data (archive, buff, size);
		hash = XXH32 (buff, size, 0);

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (pathname), "pathname", 0, false);
		ucl_object_insert_key (obj, ucl_object_fromint (size), "size", 0, false);
		ucl_object_insert_key (obj, ucl_object_fromint (hash), "hash", 0, false);
		ucl_array_append (top, obj);

		free (buff);
	}

	rspamd_controller_send_ucl (conn_ent, top);

	ucl_object_unref (top);
	archive_read_free (archive);

	return 0;
}

gpointer
init_poller_worker (struct rspamd_config *cfg)
{
	struct rspamd_poller_worker_ctx *ctx;
	//GQuark type;

	/* FIXME: use type */
	//type = g_quark_try_string ("poller");

	ctx = g_malloc0 (sizeof (struct rspamd_poller_worker_ctx));

	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	return ctx;
}

/*
 * Start worker process
 */
void
start_poller_worker (struct rspamd_worker *worker)
{
	struct rspamd_poller_worker_ctx *ctx = worker->ctx;
	struct rspamd_keypair_cache *cache;

	ctx->ev_base = rspamd_prepare_worker (worker, "poller", rspamd_poller_accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	ctx->start_time = time (NULL);
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;

	/* Accept event */
	cache = rspamd_keypair_cache_new (256);
	ctx->http = rspamd_http_router_new (rspamd_poller_error_handler,
			rspamd_poller_finish_handler, &ctx->io_tv, ctx->ev_base,
			ctx->static_files_dir, cache);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http,
				PATH_ARCHIVEINFO,
		rspamd_poller_handle_archiveinfo);
	rspamd_http_router_add_path (ctx->http,
				PATH_EXTRACTFILES,
		rspamd_poller_handle_extractfiles);

	if (ctx->key) {
		rspamd_http_router_set_key (ctx->http, ctx->key);
	}

	/* DNS resolver */
	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_init (ctx->resolver->r, ctx->ev_base);
	rspamd_upstreams_library_config (worker->srv->cfg);
	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);
	rspamd_symbols_cache_start_refresh (worker->srv->cfg->cache, ctx->ev_base);

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	rspamd_http_router_free (ctx->http);
	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
