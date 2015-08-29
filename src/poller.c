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
#include "util.h"
#include "main.h"
#include "utlist.h"
#include "main.h"
#include "libutil/map.h"
#include "libserver/worker_util.h"

#include "xxhash.h"
#include <archive.h>
#include <archive_entry.h>

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

#define PATH_ARCHIVEINFO "/archiveinfo"
#define PATH_EXTRACTFILES "/extractfiles"

#define ARCHIVE_NAME_HEADER "X-ARCHIVE-NAME"
#define ARCHIVE_MAXFILES_HEADER "X-ARCHIVE-MAXFILES"
#define MAXFILE_SIZE_HEADER "X-MAXFILE-SIZE"
#define FILTER_MASK_HEADER "X-FILTER-MASK"

extern struct rspamd_main *rspamd_main;

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
	/* Maximum file size*/
	guint32 maxsize;
	/* Maximum files */
	guint32 maxfiles;
	/* Filter mask */
	gchar *filter_mask;
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
	nsession->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
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
	struct rspamd_poller_session *session = conn_ent->ud;
	struct rspamd_poller_worker_ctx *ctx;
	struct archive *archive = NULL;
	struct archive_entry *entry = NULL;
	struct rspamd_http_header *header = NULL;
	int r;
	gsize size;
	guint errors = 0, hash = 0, curfile = 0, maxfiles, maxsize;
	gchar *archive_name = NULL, **filter_mask = NULL;
	const gchar *pathname = NULL, *format = NULL;
	void *buffer = NULL;
	ucl_object_t *top, *sub, *obj, *file_obj;

	ctx = session->ctx;

	top = ucl_object_typed_new (UCL_OBJECT);
	sub = ucl_object_typed_new (UCL_ARRAY);

	archive = archive_read_new ();
	if (archive != NULL) {
		archive_read_support_filter_all (archive);
		archive_read_support_format_all (archive);
		r = archive_read_open_memory (archive, msg->body->str, msg->body->len);
	}

	if (archive == NULL || r != ARCHIVE_OK || msg->body->len == 0) {
		msg_err ("invalid archive");
		rspamd_controller_send_error (conn_ent, 500, "invalid archive");
		return 0;
	}

	/* get options from config */
	maxsize = ctx->maxsize;
	maxfiles = ctx->maxfiles;
	filter_mask = g_strsplit_set (ctx->filter_mask, " ,", -1);

	/* get options from headers */
	LL_FOREACH (msg->headers, header) {
		gchar *header_name = NULL, *header_value = NULL;

		if (header->name)
			header_name = g_strndup (header->name->str, header->name->len);
		if (header->value)
			header_value = g_strndup (header->value->str, header->value->len);

		if (g_strcmp0 (header_name, ARCHIVE_NAME_HEADER) == 0) {
			archive_name = g_strdup (header_value);
		} else if (g_strcmp0 (header_name, ARCHIVE_MAXFILES_HEADER) == 0) {
			maxfiles = g_ascii_strtoll (header_value, NULL, 10);
		} else if (g_strcmp0 (header_name, MAXFILE_SIZE_HEADER) == 0) {
			maxsize = g_ascii_strtoll (header_value, NULL, 10);
		} else if (g_strcmp0 (header_name, FILTER_MASK_HEADER) == 0) {
			if (filter_mask)
				g_strfreev (filter_mask);
			filter_mask = g_strsplit_set (header_value, " ,", -1);
		}

		if (header_name)
			g_free (header_name);
		header_name = NULL;
		if (header_value)
			g_free (header_value);
		header_value = NULL;
	}

	r = archive_read_next_header (archive, &entry);
	format = archive_format_name (archive);
	while (r != ARCHIVE_EOF) {
		switch (r) {
			case ARCHIVE_OK: {
				gboolean match_mask = FALSE;

				size = archive_entry_size (entry);
				pathname = archive_entry_pathname (entry);

				/* handle file, else skip entry */
				if (archive_entry_filetype (entry) == AE_IFREG) {
					curfile++;

					/* finish handle archive if reached maxfiles */
					if (maxfiles && (curfile > maxfiles)) {
						msg_debug ("finish handle archive, reached maximum files: %d", maxfiles);
						r = ARCHIVE_EOF;
					} else {
						/* check if pathname not empty */
						if (g_utf8_strlen (pathname, -1) == 0) {
							errors++;
							msg_err ("file with empty pathname");
						}

						/* check if filter mask match */
						if (filter_mask) {
							for (guint i = 0; i < g_strv_length (filter_mask); i++) {
								match_mask = g_pattern_match_simple (filter_mask[i], g_utf8_casefold (pathname, -1));
								if (match_mask)
									break;
							}
						}

						/* skip entry if mask not match */
						if (filter_mask != NULL && !match_mask) {
							msg_debug ("skipping file: %s: filter mask doesn't match", pathname);
							r = archive_read_next_header (archive, &entry);
						/* skip entry if size large that allowed */
						} else if (maxsize && (size > maxsize)) {
							msg_debug ("skipping file: %s: size %d large then %d", pathname, size, maxsize);
							r = archive_read_next_header (archive, &entry);
						} else {
							buffer = g_malloc0 (size);
							r = archive_read_data (archive, buffer, size);
						}
					}
				} else {
					r = archive_read_next_header (archive, &entry);
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
				hash = XXH32 (buffer, size, 0);

				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj, ucl_object_fromint (size), "size", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromint (hash), "hash", 0, false);

				file_obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (file_obj, obj, g_strdup (pathname), 0, false);
				ucl_array_append (sub, file_obj);

				r = archive_read_next_header (archive, &entry);

				if (buffer)
					g_free (buffer);
				buffer = NULL;
			} break;
		}
	}

  obj = ucl_object_typed_new (UCL_OBJECT);
	if (archive_name) {
		ucl_object_insert_key (obj, ucl_object_fromstring (archive_name), "name", 0, false);
		g_free (archive_name);
	}
	ucl_object_insert_key (obj, ucl_object_fromstring (format), "format", 0, false);
	ucl_object_insert_key (obj, ucl_object_fromint (errors), "errors", 0, false);
	if (ucl_array_head (sub))
		ucl_object_insert_key (obj, sub, "files", 0, false);
	ucl_object_insert_key (top, obj, "archive", 0, false);

	rspamd_controller_send_ucl (conn_ent, top);

	if (filter_mask)
		g_strfreev (filter_mask);
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
	struct rspamd_http_message *reply_msg;
	struct archive *archive = NULL;
	struct archive_entry *entry = NULL;
	struct ucl_parser *parser;
	int r;
	gsize size, total_size = 0;
	guint errors = 0, hash, cur_hash, offset, ucl_size;
	gchar *ucl_str = NULL, *buffer = NULL, *buffer_hex = NULL, *buffer_tmp = NULL;
	const gchar *error, *pathname, *cur_pathname;

	ucl_object_t *top, *sub, *cur, *files_obj, *keys_obj;
	ucl_object_iter_t iter = NULL;

	parser = ucl_parser_new (UCL_PARSER_DEFAULT);
  ucl_parser_add_string (parser, msg->body->str, msg->body->len);

  if ((error = ucl_parser_get_error (parser)) != NULL) {
    msg_err ("cannot parse input: %s", error);
    rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
    ucl_parser_free (parser);
    return 0;
  }

	top = ucl_parser_get_object (parser);
  ucl_parser_free (parser);

	sub = (ucl_object_t *) ucl_object_find_key (top, "archive");
	if (top->type != UCL_OBJECT || sub == NULL) {
		msg_err ("input is not a valid data");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (top);
		return 0;
	}

	ucl_str = ucl_object_emit (top, UCL_EMIT_JSON_COMPACT);
	ucl_size = g_utf8_strlen (ucl_str, -1);

	files_obj = (ucl_object_t *) ucl_object_find_key (sub, "files");
	while ((cur = (ucl_object_t *) ucl_iterate_object (files_obj, &iter, true))) {
		ucl_object_iter_t keys_iter = NULL;
		gboolean pathname_equal = FALSE;

		if (cur->type != UCL_OBJECT) {
			msg_err ("json array data error");
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_object_unref (top);
			return 0;
		}

		keys_obj = (ucl_object_t *) ucl_iterate_object (cur, &keys_iter, true);
		pathname = ucl_copy_key_trash (keys_obj);

		archive = archive_read_new ();

		if (archive != NULL) {
			archive_read_support_filter_all (archive);
			archive_read_support_format_all (archive);
			r = archive_read_open_memory (archive, msg->body->str + ucl_size, msg->body->len - ucl_size);
		}

		if (archive == NULL || r != ARCHIVE_OK) {
			msg_err ("invalid archive");
			rspamd_controller_send_error (conn_ent, 500, "invalid archive");
			return 0;
		}

		r = archive_read_next_header (archive, &entry);
		while (r != ARCHIVE_EOF) {
			switch (r) {
				case ARCHIVE_OK: {
					cur_pathname = archive_entry_pathname (entry);
					if (g_strcmp0 (g_utf8_casefold (pathname, -1), cur_pathname) == 0 &&
							archive_entry_filetype (entry) == AE_IFREG) {
						pathname_equal = TRUE;
						size = ucl_obj_toint (ucl_object_find_key (keys_obj, "size"));
						hash = ucl_obj_toint (ucl_object_find_key (keys_obj, "hash"));

						buffer_tmp = g_malloc (size);
						r = archive_read_data (archive, buffer_tmp, size);
						cur_hash = XXH32 (buffer_tmp, size, 0);

						if (cur_hash == hash) {
							total_size += size;
							offset = total_size - size;

							if (buffer == NULL) {
								buffer = g_malloc0 (size);
							} else {
								buffer = g_realloc (buffer, total_size);
							}
							memcpy (buffer + offset, buffer_tmp, size);

							/* update offset in ucl */
							ucl_object_replace_key (keys_obj, ucl_object_fromint (offset), "offset", 0, false);
						} else {
							/* mark object with bad hash */
							errors++;
							msg_err ("skipping file: %s: bad hash", pathname);
							ucl_object_replace_key (keys_obj, ucl_object_fromint (0), "hash", 0, false);
						}

						if (buffer_tmp)
							g_free (buffer_tmp);
					} else {
						r = archive_read_next_header (archive, &entry);
					}
				} break;
				case ARCHIVE_WARN:
				case ARCHIVE_FAILED: {
					errors++;
					msg_err (archive_error_string (archive));
					r = archive_read_next_header (archive, &entry);
				} break;
				case ARCHIVE_FATAL:
				default: {
					r = ARCHIVE_EOF;
				} break;
			}
		}

		if (!pathname_equal) {
			/* mark object as empty */
			errors++;
			msg_err ("archive doesn't contain file: %s", pathname);
			ucl_object_replace_key (keys_obj, ucl_object_fromint (0), "size", 0, false);
		}
		archive_read_free (archive);
	}

	/* delete empty objects */
	iter = NULL;
	while ((cur = (ucl_object_t *) ucl_iterate_object (files_obj, &iter, true))) {
		ucl_object_iter_t keys_iter = NULL;

		keys_obj = (ucl_object_t *) ucl_iterate_object (cur, &keys_iter, true);
		size = ucl_obj_toint (ucl_object_find_key (keys_obj, "size"));
		hash = ucl_obj_toint (ucl_object_find_key (keys_obj, "hash"));

		if (size == 0 || hash == 0) {
			ucl_array_delete (files_obj, cur);

			/* iterate from first element */
			iter = NULL;
		}
	}

	/* convert buffer to hex */
	buffer_hex = g_malloc (total_size * 2 + 1);
	for (guint i = 0; i < total_size; i++) {
		g_snprintf (buffer_hex + i * 2, 3, "%02x", (guint) (*((guint8 *) (buffer + i))));
	}

	/* update errors in ucl */
	ucl_object_replace_key (sub, ucl_object_fromint (errors), "errors", 0, false);

	/* delete files key in ucl */
	if (ucl_array_head (files_obj) == NULL)
		ucl_object_delete_key (sub, "files");

	ucl_str = ucl_object_emit (top, UCL_EMIT_JSON_COMPACT);
	ucl_size = g_utf8_strlen (ucl_str, -1);

	reply_msg = rspamd_http_new_message (HTTP_RESPONSE);
	rspamd_http_message_add_header (reply_msg, "X-UCL-SIZE", g_strdup_printf ("%i", ucl_size));
	reply_msg->date = time (NULL);
	reply_msg->code = 200;
	reply_msg->body = g_string_new (ucl_str);
	g_string_append (reply_msg->body, buffer_hex);
	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn,
		reply_msg,
		NULL,
		"application/json",
		conn_ent,
		conn_ent->conn->fd,
		conn_ent->rt->ptv,
		conn_ent->rt->ev_base);
		conn_ent->is_reply = TRUE;

	ucl_object_unref (top);
	if (buffer)
		g_free (buffer);
	if (buffer_hex)
	 g_free (buffer_hex);

	return 0;
}

gpointer
init_poller_worker (struct rspamd_config *cfg)
{
	struct rspamd_poller_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("poller");

	ctx = g_malloc0 (sizeof (struct rspamd_poller_worker_ctx));

	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg, type, "maxsize",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_poller_worker_ctx, maxsize), 0);
	rspamd_rcl_register_worker_option (cfg, type, "maxfiles",
		rspamd_rcl_parse_struct_integer, ctx,
		G_STRUCT_OFFSET (struct rspamd_poller_worker_ctx, maxfiles), 0);
	rspamd_rcl_register_worker_option (cfg, type, "filter_mask",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_poller_worker_ctx, filter_mask), 0);

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
