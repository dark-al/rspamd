/* Copyright (c) 2010-2012, Vsevolod Stakhov
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
#include "libserver/dynamic_cfg.h"
#include "libutil/rrd.h"
#include "libutil/map.h"
#include "libstat/stat_api.h"
#include "main.h"
#include "libserver/worker_util.h"
#include "utlist.h"

#include "blake2.h" 
#include "cryptobox.h"
#include "ottery.h"

/* 60 seconds for worker's IO */
#define DEFAULT_WORKER_IO_TIMEOUT 60000

/* HTTP paths */
#define PATH_AUTH "/auth"
#define PATH_SYMBOLS "/symbols"
#define PATH_ACTIONS "/actions"
#define PATH_MAPS "/maps"
#define PATH_GET_MAP "/getmap"
#define PATH_GRAPH "/graph"
#define PATH_PIE_CHART "/pie"
#define PATH_HISTORY "/history"
#define PATH_LEARN_SPAM "/learnspam"
#define PATH_LEARN_HAM "/learnham"
#define PATH_SAVE_ACTIONS "/saveactions"
#define PATH_SAVE_SYMBOLS "/savesymbols"
#define PATH_SAVE_MAP "/savemap"
#define PATH_SCAN "/scan"
#define PATH_CHECK "/check"
#define PATH_STAT "/stat"
#define PATH_STAT_RESET "/statreset"
#define PATH_COUNTERS "/counters"

/* Graph colors */
#define COLOR_CLEAN "#58A458"
#define COLOR_PROBABLE_SPAM "#D67E7E"
#define COLOR_GREYLIST "#A0A0A0"
#define COLOR_REJECT "#CB4B4B"
#define COLOR_TOTAL "#9440ED"

#define RSPAMD_PBKDF_ID_V1 1

extern struct rspamd_main *rspamd_main;
gpointer init_controller_worker (struct rspamd_config *cfg);
void start_controller_worker (struct rspamd_worker *worker);

worker_t controller_worker = {
	"controller",                   /* Name */
	init_controller_worker,         /* Init function */
	start_controller_worker,        /* Start function */
	TRUE,                   /* Has socket */
	TRUE,                   /* Non unique */
	FALSE,                  /* Non threaded */
	TRUE,                   /* Killable */
	SOCK_STREAM             /* TCP socket */
};
/*
 * Worker's context
 */
struct rspamd_controller_worker_ctx {
	guint32 timeout;
	struct timeval io_tv;
	/* DNS resolver */
	struct rspamd_dns_resolver *resolver;
	/* Events base */
	struct event_base *ev_base;
	/* Whether we use ssl for this server */
	gboolean use_ssl;
	/* Webui password */
	gchar *password;
	/* Privilleged password */
	gchar *enable_password;
	/* HTTP server */
	struct rspamd_http_connection_router *http;
	/* Server's start time */
	time_t start_time;
	/* Main server */
	struct rspamd_main *srv;
	/* Configuration */
	struct rspamd_config *cfg;
	/* SSL cert */
	gchar *ssl_cert;
	/* SSL private key */
	gchar *ssl_key;
	/* A map of secure IP */
	GList *secure_ip;
	radix_compressed_t *secure_map;

	/* Static files dir */
	gchar *static_files_dir;

	/* Custom commands registered by plugins */
	GHashTable *custom_commands;

	/* Worker */
	struct rspamd_worker *worker;

	/* Local keypair */
	gpointer key;
};

struct rspamd_controller_session {
	struct rspamd_controller_worker_ctx *ctx;
	rspamd_mempool_t *pool;
	struct rspamd_task *task;
	struct rspamd_classifier_config *cl;
	rspamd_inet_addr_t *from_addr;
	gboolean is_spam;
};


const struct rspamd_controller_pbkdf pbkdf_list[] = {
	{
		.id = RSPAMD_PBKDF_ID_V1,
		.rounds = 16000,
		.salt_len = 20,
		.key_len = BLAKE2B_OUTBYTES / 2
	}
};

static gboolean
rspamd_constant_memcmp (const guchar *a, const guchar *b, gsize len)
{
	gsize lena, lenb, i;
	gint acc = 0;

	if (len == 0) {
		lena = strlen (a);
		lenb = strlen (b);

		if (lena != lenb) {
			return FALSE;
		}

		len = lena;
	}

	for (i = 0; i < len; i ++) {
		acc |= a[i] ^ b[i];
	}

	return acc == 0;
}

static gboolean
rspamd_is_encrypted_password (const gchar *password,
		struct rspamd_controller_pbkdf const **pbkdf)
{
	const gchar *start, *end;
	gint64 id;
	gsize size;
	gboolean ret = FALSE;

	if (password[0] == '$') {
		/* Parse id */
		start = password + 1;
		end = start;
		size = 0;

		while (*end != '\0' && g_ascii_isdigit (*end)) {
			size++;
			end++;
		}

		if (size > 0) {
			gchar *endptr;
			id = strtoul (start, &endptr, 10);

			if ((endptr == NULL || *endptr == *end) && id == RSPAMD_PBKDF_ID_V1) {
				ret = TRUE;

				if (pbkdf != NULL) {
					*pbkdf = &pbkdf_list[0];
				}
			}
		}
	}

	return ret;
}

static const gchar *
rspamd_encrypted_password_get_str (const gchar * password, gsize skip,
		gsize * length)
{
	const gchar *str, *start, *end;
	gsize size;

	start = password + skip;
	end = start;
	size = 0;

	while (*end != '\0' && g_ascii_isalnum (*end)) {
		size++;
		end++;
	}

	if (size) {
		str = start;
		*length = size;
	}
	else {
		str = NULL;
	}

	return str;
}

static gboolean rspamd_check_encrypted_password (const GString * password,
		const gchar * check, const struct rspamd_controller_pbkdf *pbkdf)
{
	const gchar *salt, *hash;
	gchar *salt_decoded, *key_decoded;
	gsize salt_len, key_len;
	gboolean ret = TRUE;
	guchar *local_key;

	g_assert (pbkdf != NULL);
	/* get salt */
	salt = rspamd_encrypted_password_get_str (check, 3, &salt_len);
	/* get hash */
	hash = rspamd_encrypted_password_get_str (check, 3 + salt_len + 1,
			&key_len);
	if (salt != NULL && hash != NULL) {

		/* decode salt */
		salt_decoded = rspamd_decode_base32 (salt, salt_len, &salt_len);

		if (salt_decoded == NULL || salt_len != pbkdf->salt_len) {
			/* We have some unknown salt here */
			msg_info ("incorrect salt: %z, while %z expected",
					salt_len, pbkdf->salt_len);
			return FALSE;
		}

		key_decoded = rspamd_decode_base32 (hash, key_len, &key_len);

		if (key_decoded == NULL || key_len != pbkdf->key_len) {
			/* We have some unknown salt here */
			msg_info ("incorrect key: %z, while %z expected",
					key_len, pbkdf->key_len);
			return FALSE;
		}

		local_key = g_alloca (pbkdf->key_len);
		rspamd_cryptobox_pbkdf (password->str, password->len,
				salt_decoded, salt_len,
				local_key, pbkdf->key_len, pbkdf->rounds);

		if (!rspamd_constant_memcmp (key_decoded, local_key, pbkdf->key_len)) {
			msg_info ("incorrect or absent password has been specified");
			ret = FALSE;
		}

		g_free (salt_decoded);
		g_free (key_decoded);
	}

	return ret;
}

/* Check for password if it is required by configuration */
static gboolean rspamd_controller_check_password(
		struct rspamd_http_connection_entry *entry,
		struct rspamd_controller_session *session,
		struct rspamd_http_message *msg, gboolean is_enable)
{
	const gchar *check;
	const GString *password;
	GString lookup;
	GHashTable *query_args = NULL;
	struct rspamd_controller_worker_ctx *ctx = session->ctx;
	gboolean check_normal = TRUE, check_enable = TRUE, ret = TRUE;
	const struct rspamd_controller_pbkdf *pbkdf = NULL;

	/* Access list logic */
	if (rspamd_inet_address_get_af (session->from_addr) == AF_UNIX) {
		msg_info ("allow unauthorized connection from a unix socket");
		return TRUE;
	}
	else if (ctx->secure_map
			&& radix_find_compressed_addr (ctx->secure_map, session->from_addr)
					!= RADIX_NO_VALUE) {
		msg_info ("allow unauthorized connection from a trusted IP %s",
				rspamd_inet_address_to_string (session->from_addr));
		return TRUE;
	}

	/* Password logic */
	password = rspamd_http_message_find_header (msg, "Password");

	if (password == NULL) {
		/* Try to get password from query args */
		query_args = rspamd_http_message_parse_query (msg);

		lookup.str = (gchar *)"password";
		lookup.len = sizeof ("password") - 1;

		password = g_hash_table_lookup (query_args, &lookup);
	}

	if (password == NULL) {

		if (query_args != NULL) {
			g_hash_table_unref (query_args);
		}

		if (ctx->secure_map == NULL) {
			if (ctx->password == NULL && !is_enable) {
				return TRUE;
			}
			else if (is_enable && (ctx->password == NULL &&
					ctx->enable_password == NULL)) {
				return TRUE;
			}
		}
		msg_info ("absent password has been specified");
		ret = FALSE;
	}
	else {
		if (is_enable) {
			/* For privileged commands we strictly require enable password */
			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;
			}
			else {
				/* Use just a password (legacy mode) */
				msg_info(
						"using password as enable_password for a privileged command");
				check = ctx->password;
			}
			if (check != NULL) {
				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					ret = rspamd_constant_memcmp (password->str, check, password->len);
				}
				else {
					ret = rspamd_check_encrypted_password (password, check,
							pbkdf);
				}
			}
			else {
				msg_warn (
						"no password to check while executing a privileged command");
				if (ctx->secure_map) {
					msg_info("deny unauthorized connection");
					ret = FALSE;
				}
				ret = FALSE;
			}
		}
		else {
			/* Accept both normal and enable passwords */
			if (ctx->password != NULL) {
				check = ctx->password;
				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_normal = rspamd_constant_memcmp (password->str, check,
							password->len);
				}
				else {
					check_normal = rspamd_check_encrypted_password (password,
							check, pbkdf);
				}

			}
			else {
				check_normal = FALSE;
			}
			if (ctx->enable_password != NULL) {
				check = ctx->enable_password;
				if (!rspamd_is_encrypted_password (check, &pbkdf)) {
					check_enable = rspamd_constant_memcmp (password->str, check,
							password->len);
				}
				else {
					check_enable = rspamd_check_encrypted_password (password,
							check, pbkdf);
				}
			}
			else {
				check_enable = FALSE;
			}
		}
	}

	if (query_args != NULL) {
		g_hash_table_unref (query_args);
	}

	if (check_normal == FALSE && check_enable == FALSE) {
		msg_info("absent or incorrect password has been specified");
		ret = FALSE;
	}

	if (!ret) {
		rspamd_controller_send_error (entry, 403, "Unauthorized");
	}

	return ret;
}

/* Command handlers */

/*
 * Auth command handler:
 * request: /auth
 * headers: Password
 * reply: json {"auth": "ok", "version": "0.5.2", "uptime": "some uptime", "error": "none"}
 */
static int
rspamd_controller_handle_auth (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_stat *st;
	int64_t uptime;
	gulong data[4];
	ucl_object_t *obj;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	obj = ucl_object_typed_new (UCL_OBJECT);
	st = session->ctx->srv->stat;
	data[0] = st->actions_stat[METRIC_ACTION_NOACTION];
	data[1] = st->actions_stat[METRIC_ACTION_ADD_HEADER] +
		st->actions_stat[METRIC_ACTION_REWRITE_SUBJECT];
	data[2] = st->actions_stat[METRIC_ACTION_GREYLIST];
	data[3] = st->actions_stat[METRIC_ACTION_REJECT];

	/* Get uptime */
	uptime = time (NULL) - session->ctx->start_time;

	ucl_object_insert_key (obj, ucl_object_fromstring (
			RVERSION),			   "version",  0, false);
	ucl_object_insert_key (obj, ucl_object_fromstring (
			"ok"),				   "auth",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			uptime),			   "uptime",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[0]),			   "clean",	   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[1]),			   "probable", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[2]),			   "greylist", 0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			data[3]),			   "reject",   0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_scanned), "scanned",  0, false);
	ucl_object_insert_key (obj,	   ucl_object_fromint (
			st->messages_learned), "learned",  0, false);

	rspamd_controller_send_ucl (conn_ent, obj);
	ucl_object_unref (obj);

	return 0;
}

/*
 * Symbols command handler:
 * request: /symbols
 * reply: json [{
 *  "name": "group_name",
 *  "symbols": [
 *      {
 *      "name": "name",
 *      "weight": 0.1,
 *      "description": "description of symbol"
 *      },
 *      {...}
 * },
 * {...}]
 */
static int
rspamd_controller_handle_symbols (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GHashTableIter it, sit;
	struct rspamd_symbols_group *gr;
	struct rspamd_symbol_def *sym;
	struct metric *metric;
	ucl_object_t *obj, *top, *sym_obj, *group_symbols;
	gpointer k, v;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Go through all symbols groups in the default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	g_assert (metric != NULL);
	g_hash_table_iter_init (&it, metric->groups);

	while (g_hash_table_iter_next (&it, &k, &v)) {
		gr = v;
		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj, ucl_object_fromstring (
				gr->name), "group", 0, false);
		/* Iterate through all symbols */

		g_hash_table_iter_init (&sit, gr->symbols);
		group_symbols = ucl_object_typed_new (UCL_ARRAY);

		while (g_hash_table_iter_next (&sit, &k, &v)) {
			sym = v;
			sym_obj = ucl_object_typed_new (UCL_OBJECT);

			ucl_object_insert_key (sym_obj, ucl_object_fromstring (sym->name),
				"symbol", 0, false);
			ucl_object_insert_key (sym_obj,
				ucl_object_fromdouble (*sym->weight_ptr),
				"weight", 0, false);
			if (sym->description) {
				ucl_object_insert_key (sym_obj,
					ucl_object_fromstring (sym->description),
					"description", 0, false);
			}

			ucl_array_append (group_symbols, sym_obj);
		}

		ucl_object_insert_key (obj, group_symbols, "rules", 0, false);
		ucl_array_append (top, obj);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Actions command handler:
 * request: /actions
 * reply: json [{
 *  "action": "no action",
 *  "value": 1.1
 * },
 * {...}]
 */
static int
rspamd_controller_handle_actions (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct metric *metric;
	struct metric_action *act;
	gint i;
	ucl_object_t *obj, *top;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Get actions for default metric */
	metric = g_hash_table_lookup (session->ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric != NULL) {
		for (i = METRIC_ACTION_REJECT; i < METRIC_ACTION_MAX; i++) {
			act = &metric->actions[i];
			if (act->score >= 0) {
				obj = ucl_object_typed_new (UCL_OBJECT);
				ucl_object_insert_key (obj,
					ucl_object_fromstring (rspamd_action_to_str (
						act->action)), "action", 0, false);
				ucl_object_insert_key (obj, ucl_object_fromdouble (
						act->score), "value", 0, false);
				ucl_array_append (top, obj);
			}
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}
/*
 * Maps command handler:
 * request: /maps
 * headers: Password
 * reply: json [
 *      {
 *      "map": "name",
 *      "description": "description",
 *      "editable": true
 *      },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_maps (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur, *tmp = NULL;
	struct rspamd_map *map;
	gboolean editable;
	ucl_object_t *obj, *top;


	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	/* Iterate over all maps */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->protocol == MAP_PROTO_FILE) {
			if (access (map->uri, R_OK) == 0) {
				tmp = g_list_prepend (tmp, map);
			}
		}
		cur = g_list_next (cur);
	}
	/* Iterate over selected maps */
	cur = tmp;
	while (cur) {
		map = cur->data;
		editable = (access (map->uri, W_OK) == 0);

		obj = ucl_object_typed_new (UCL_OBJECT);
		ucl_object_insert_key (obj,	   ucl_object_fromint (map->id),
			"map", 0, false);
		if (map->description) {
			ucl_object_insert_key (obj, ucl_object_fromstring (map->description),
					"description", 0, false);
		}
		ucl_object_insert_key (obj,	  ucl_object_frombool (editable),
			"editable", 0, false);
		ucl_array_append (top, obj);

		cur = g_list_next (cur);
	}

	if (tmp) {
		g_list_free (tmp);
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * Get map command handler:
 * request: /getmap
 * headers: Password, Map
 * reply: plain-text
 */
static int
rspamd_controller_handle_get_map (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	const GString *idstr;
	gchar *errstr;
	struct stat st;
	gint fd;
	guint32 id;
	gboolean found = FALSE;
	struct rspamd_http_message *reply;


	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "400 id header missing");
		return 0;
	}

	id = strtoul (idstr->str, &errstr, 10);
	if (*errstr != '\0' && !g_ascii_isspace (*errstr)) {
		msg_info ("invalid map id");
		rspamd_controller_send_error (conn_ent, 400, "400 invalid map id");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = session->ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found");
		rspamd_controller_send_error (conn_ent, 404, "404 map not found");
		return 0;
	}

	if (stat (map->uri, &st) == -1 || (fd = open (map->uri, O_RDONLY)) == -1) {
		msg_err ("cannot open map %s: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map open error");
		return 0;
	}

	reply = rspamd_http_new_message (HTTP_RESPONSE);
	reply->date = time (NULL);
	reply->code = 200;
	reply->body = g_string_sized_new (st.st_size);

	/* Read the whole buffer */
	if (read (fd, reply->body->str, st.st_size) == -1) {
		close (fd);
		rspamd_http_message_free (reply);
		msg_err ("cannot read map %s: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 500, "500 map read error");
		return 0;
	}

	reply->body->len = st.st_size;
	reply->body->str[reply->body->len] = '\0';

	close (fd);

	rspamd_http_connection_reset (conn_ent->conn);
	rspamd_http_connection_write_message (conn_ent->conn, reply, NULL,
		"text/plain", conn_ent, conn_ent->conn->fd,
		conn_ent->rt->ptv, conn_ent->rt->ev_base);
	conn_ent->is_reply = TRUE;

	return 0;
}

static ucl_object_t *
rspamd_controller_pie_element (enum rspamd_metric_action action,
		const char *label, gdouble data)
{
	ucl_object_t *res = ucl_object_typed_new (UCL_OBJECT);
	const char *colors[METRIC_ACTION_MAX] = {
		[METRIC_ACTION_REJECT] = "#993300",
		[METRIC_ACTION_SOFT_REJECT] = "#cc9966",
		[METRIC_ACTION_REWRITE_SUBJECT] = "#ff6600",
		[METRIC_ACTION_ADD_HEADER] = "#ffcc66",
		[METRIC_ACTION_GREYLIST] = "#6666cc",
		[METRIC_ACTION_NOACTION] = "#66cc00"
	};

	ucl_object_insert_key (res, ucl_object_fromstring (colors[action]),
			"color", 0, false);
	ucl_object_insert_key (res, ucl_object_fromstring (label), "label", 0, false);
	ucl_object_insert_key (res, ucl_object_fromdouble (data), "data", 0, false);

	return res;
}

/*
 * Pie chart command handler:
 * request: /pie
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_pie_chart (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	gdouble data[5], total;
	ucl_object_t *top;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);
	total = ctx->srv->stat->messages_scanned;
	if (total != 0) {

		data[0] = ctx->srv->stat->actions_stat[METRIC_ACTION_NOACTION] / total *
			100.;
		data[1] = ctx->srv->stat->actions_stat[METRIC_ACTION_SOFT_REJECT] / total *
			100.;
		data[2] = (ctx->srv->stat->actions_stat[METRIC_ACTION_ADD_HEADER] +
			ctx->srv->stat->actions_stat[METRIC_ACTION_REWRITE_SUBJECT]) /
			total * 100.;
		data[3] = ctx->srv->stat->actions_stat[METRIC_ACTION_GREYLIST] / total *
			100.;
		data[4] = ctx->srv->stat->actions_stat[METRIC_ACTION_REJECT] / total *
			100.;
	}
	else {
		memset (data, 0, sizeof (data));
	}
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_NOACTION, "Clean", data[0]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_SOFT_REJECT, "Temporary rejected", data[1]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_ADD_HEADER, "Probable spam", data[2]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_GREYLIST, "Greylisted", data[3]));
	ucl_array_append (top, rspamd_controller_pie_element (
			METRIC_ACTION_REJECT, "Rejected", data[4]));

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

/*
 * History command handler:
 * request: /history
 * headers: Password
 * reply: json [
 *      { label: "Foo", data: 11 },
 *      { label: "Bar", data: 20 },
 *      {...}
 * ]
 */
static int
rspamd_controller_handle_history (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct roll_history_row *row;
	struct roll_history copied_history;
	gint i, rows_proc, row_num;
	struct tm *tm;
	gchar timebuf[32];
	ucl_object_t *top, *obj;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	top = ucl_object_typed_new (UCL_ARRAY);

	/* Set lock on history */
	rspamd_mempool_lock_mutex (ctx->srv->history->mtx);
	ctx->srv->history->need_lock = TRUE;
	/* Copy locked */
	memcpy (&copied_history, ctx->srv->history, sizeof (copied_history));
	rspamd_mempool_unlock_mutex (ctx->srv->history->mtx);

	/* Go through all rows */
	row_num = copied_history.cur_row;
	for (i = 0, rows_proc = 0; i < HISTORY_MAX_ROWS; i++, row_num++) {
		if (row_num == HISTORY_MAX_ROWS) {
			row_num = 0;
		}
		row = &copied_history.rows[row_num];
		/* Get only completed rows */
		if (row->completed) {
			tm = localtime (&row->tv.tv_sec);
			strftime (timebuf, sizeof (timebuf) - 1, "%Y-%m-%d %H:%M:%S", tm);
			obj = ucl_object_typed_new (UCL_OBJECT);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					timebuf),		  "time", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->message_id), "id",	  0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (row->from_addr),
					"ip", 0, false);
			ucl_object_insert_key (obj,
				ucl_object_fromstring (rspamd_action_to_str (
					row->action)), "action", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromdouble (
					row->score),		  "score",			0, false);
			ucl_object_insert_key (obj,
				ucl_object_fromdouble (
					row->required_score), "required_score", 0, false);
			ucl_object_insert_key (obj, ucl_object_fromstring (
					row->symbols),		  "symbols",		0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromint (
					row->len),			  "size",			0, false);
			ucl_object_insert_key (obj,	   ucl_object_fromint (
					row->scan_time),	  "scan_time",		0, false);
			if (row->user[0] != '\0') {
				ucl_object_insert_key (obj, ucl_object_fromstring (
						row->user), "user", 0, false);
			}
			ucl_array_append (top, obj);
			rows_proc++;
		}
	}

	rspamd_controller_send_ucl (conn_ent, top);
	ucl_object_unref (top);

	return 0;
}

static gboolean
rspamd_controller_learn_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_controller_session *session;
	struct rspamd_http_connection_entry *conn_ent;
	GError *err = NULL;

	conn_ent = task->fin_arg;
	session = conn_ent->ud;

	if (rspamd_learn_task_spam (session->cl, task, session->is_spam, &err) ==
			RSPAMD_STAT_PROCESS_ERROR) {
		msg_info ("cannot learn <%s>: %e", task->message_id, err);
		rspamd_controller_send_error (conn_ent, err->code, err->message);

		return TRUE;
	}
	/* Successful learn */
	msg_info ("<%s> learned message as %s: %s",
		rspamd_inet_address_to_string (session->from_addr),
		session->is_spam ? "spam" : "ham",
		task->message_id);
	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return TRUE;
}

static gboolean
rspamd_controller_check_fin_task (void *ud)
{
	struct rspamd_task *task = ud;
	struct rspamd_http_connection_entry *conn_ent;
	struct rspamd_http_message *msg;

	/* Task is already finished or skipped */
	if (RSPAMD_TASK_IS_PROCESSED (task) || !rspamd_task_process (task,
			RSPAMD_TASK_PROCESS_ALL)) {
		conn_ent = task->fin_arg;
		msg = rspamd_http_new_message (HTTP_RESPONSE);
		msg->date = time (NULL);
		msg->code = 200;
		rspamd_protocol_http_reply (msg, task);
		rspamd_http_connection_reset (conn_ent->conn);
		rspamd_http_connection_write_message (conn_ent->conn, msg, NULL,
				"application/json", conn_ent, conn_ent->conn->fd, conn_ent->rt->ptv,
				conn_ent->rt->ev_base);
		conn_ent->is_reply = TRUE;
		return TRUE;
	}

	/* One more iteration */
	return FALSE;
}

static int
rspamd_controller_handle_learn_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean is_spam)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_classifier_config *cl;
	struct rspamd_task *task;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	/* XXX: now work with only bayes */
	cl = rspamd_config_find_classifier (ctx->cfg, "bayes");
	if (cl == NULL) {
		rspamd_controller_send_error (conn_ent, 400, "Classifier not found");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker);

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;


	task->s = rspamd_session_create (session->pool,
			rspamd_controller_learn_fin_task,
			NULL,
			rspamd_task_free_hard,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;


	if (!rspamd_task_load_message (task, msg, msg->body->str, msg->body->len)) {
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_LEARN)) {
		msg_warn ("message cannot be processed for %s", task->message_id);
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	session->task = task;
	session->cl = cl;
	session->is_spam = is_spam;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Learn spam command handler:
 * request: /learnspam
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnspam (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, TRUE);
}
/*
 * Learn ham command handler:
 * request: /learnham
 * headers: Password
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_learnham (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	return rspamd_controller_handle_learn_common (conn_ent, msg, FALSE);
}

/*
 * Scan command handler:
 * request: /scan
 * headers: Password
 * input: plaintext data
 * reply: json {scan data} or {"error":"error message"}
 */
static int
rspamd_controller_handle_scan (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	task = rspamd_task_new (session->ctx->worker);
	task->ev_base = session->ctx->ev_base;

	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_check_fin_task,
			NULL,
			rspamd_task_free_hard,
			task);
	task->fin_arg = conn_ent;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);
	task->sock = conn_ent->conn->fd;

	if (!rspamd_task_load_message (task, msg, msg->body->str, msg->body->len)) {
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	if (!rspamd_task_process (task, RSPAMD_TASK_PROCESS_ALL)) {
		msg_warn ("message cannot be processed for %s", task->message_id);
		rspamd_controller_send_error (conn_ent, task->err->code, task->err->message);
		rspamd_session_destroy (task->s);
		return 0;
	}

	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

/*
 * Save actions command handler:
 * request: /saveactions
 * headers: Password
 * input: json array [<spam>,<probable spam>,<greylist>]
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_saveactions (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble score;
	gint i, added = 0;
	enum rspamd_metric_action act;
	ucl_object_iter_t it = NULL;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body->str, msg->body->len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY || obj->len != 3) {
		msg_err ("input is not an array of 3 elements");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	for (i = 0; i < 3; i++) {
		cur = ucl_iterate_object (obj, &it, TRUE);
		if (cur == NULL) {
			break;
		}
		switch (i) {
		case 0:
			act = METRIC_ACTION_REJECT;
			break;
		case 1:
			act = METRIC_ACTION_ADD_HEADER;
			break;
		case 2:
			act = METRIC_ACTION_GREYLIST;
			break;
		}
		score = ucl_object_todouble (cur);
		if (metric->actions[act].score != score) {
			add_dynamic_action (ctx->cfg, DEFAULT_METRIC, act, score);
			added ++;
		}
	}

	if (dump_dynamic_config (ctx->cfg)) {
		msg_info ("<%s> modified %d actions",
			rspamd_inet_address_to_string (session->from_addr),
			added);

		rspamd_controller_send_string (conn_ent, "{\"success\":true}");
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Save error");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save symbols command handler:
 * request: /savesymbols
 * headers: Password
 * input: json data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savesymbols (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct ucl_parser *parser;
	struct metric *metric;
	ucl_object_t *obj;
	const ucl_object_t *cur, *jname, *jvalue;
	ucl_object_iter_t iter = NULL;
	struct rspamd_controller_worker_ctx *ctx;
	const gchar *error;
	gdouble val;
	struct rspamd_symbol_def *sym;
	int added = 0;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	metric = g_hash_table_lookup (ctx->cfg->metrics, DEFAULT_METRIC);
	if (metric == NULL) {
		msg_err ("cannot find default metric");
		rspamd_controller_send_error (conn_ent, 500,
			"Default metric is absent");
		return 0;
	}

	/* Now check for dynamic config */
	if (!ctx->cfg->dynamic_conf) {
		msg_err ("dynamic conf has not been defined");
		rspamd_controller_send_error (conn_ent,
			500,
			"No dynamic_rules setting defined");
		return 0;
	}

	parser = ucl_parser_new (0);
	ucl_parser_add_chunk (parser, msg->body->str, msg->body->len);

	if ((error = ucl_parser_get_error (parser)) != NULL) {
		msg_err ("cannot parse input: %s", error);
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_parser_free (parser);
		return 0;
	}

	obj = ucl_parser_get_object (parser);
	ucl_parser_free (parser);

	if (obj->type != UCL_ARRAY) {
		msg_err ("input is not an array");
		rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
		ucl_object_unref (obj);
		return 0;
	}

	while ((cur = ucl_iterate_object (obj, &iter, true))) {
		if (cur->type != UCL_OBJECT) {
			msg_err ("json array data error");
			rspamd_controller_send_error (conn_ent, 400, "Cannot parse input");
			ucl_object_unref (obj);
			return 0;
		}
		jname = ucl_object_find_key (cur, "name");
		jvalue = ucl_object_find_key (cur, "value");
		val = ucl_object_todouble (jvalue);
		sym =
			g_hash_table_lookup (metric->symbols, ucl_object_tostring (jname));
		if (sym && fabs (*sym->weight_ptr - val) > 0.01) {
			if (!add_dynamic_symbol (ctx->cfg, DEFAULT_METRIC,
				ucl_object_tostring (jname), val)) {
				msg_err ("add symbol failed for %s",
					ucl_object_tostring (jname));
				rspamd_controller_send_error (conn_ent, 506,
					"Add symbol failed");
				ucl_object_unref (obj);
				return 0;
			}
			added ++;
		}
	}

	if (added > 0) {
		if (dump_dynamic_config (ctx->cfg)) {
			msg_info ("<%s> modified %d symbols",
					rspamd_inet_address_to_string (session->from_addr),
					added);

			rspamd_controller_send_string (conn_ent, "{\"success\":true}");
		}
		else {
			rspamd_controller_send_error (conn_ent, 500, "Save error");
		}
	}
	else {
		msg_err ("no symbols to save");
		rspamd_controller_send_error (conn_ent, 404, "No symbols to save");
	}

	ucl_object_unref (obj);

	return 0;
}

/*
 * Save map command handler:
 * request: /savemap
 * headers: Password, Map
 * input: plaintext data
 * reply: json {"success":true} or {"error":"error message"}
 */
static int
rspamd_controller_handle_savemap (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	GList *cur;
	struct rspamd_map *map;
	struct rspamd_controller_worker_ctx *ctx;
	const GString *idstr;
	gchar *errstr;
	guint32 id;
	gboolean found = FALSE;
	gint fd;

	ctx = session->ctx;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	if (msg->body == NULL || msg->body->len == 0) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	idstr = rspamd_http_message_find_header (msg, "Map");

	if (idstr == NULL) {
		msg_info ("absent map id");
		rspamd_controller_send_error (conn_ent, 400, "Map id not specified");
		return 0;
	}

	id = strtoul (idstr->str, &errstr, 10);
	if (*errstr != '\0' && !g_ascii_isspace (*errstr)) {
		msg_info ("invalid map id: %V", idstr);
		rspamd_controller_send_error (conn_ent, 400, "Map id is invalid");
		return 0;
	}

	/* Now let's be sure that we have map defined in configuration */
	cur = ctx->cfg->maps;
	while (cur) {
		map = cur->data;
		if (map->id == id && map->protocol == MAP_PROTO_FILE) {
			found = TRUE;
			break;
		}
		cur = g_list_next (cur);
	}

	if (!found) {
		msg_info ("map not found: %d", id);
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	if (g_atomic_int_get (map->locked)) {
		msg_info ("map locked: %s", map->uri);
		rspamd_controller_send_error (conn_ent, 404, "Map is locked");
		return 0;
	}

	/* Set lock */
	g_atomic_int_set (map->locked, 1);
	fd = open (map->uri, O_WRONLY | O_TRUNC);
	if (fd == -1) {
		g_atomic_int_set (map->locked, 0);
		msg_info ("map %s open error: %s", map->uri, strerror (errno));
		rspamd_controller_send_error (conn_ent, 404, "Map id not found");
		return 0;
	}

	if (write (fd, msg->body->str, msg->body->len) == -1) {
		msg_info ("map %s write error: %s", map->uri, strerror (errno));
		close (fd);
		g_atomic_int_set (map->locked, 0);
		rspamd_controller_send_error (conn_ent, 500, "Map write error");
		return 0;
	}

	msg_info ("<%s>, map %s saved",
		rspamd_inet_address_to_string (session->from_addr),
		map->uri);
	/* Close and unlock */
	close (fd);
	g_atomic_int_set (map->locked, 0);

	rspamd_controller_send_string (conn_ent, "{\"success\":true}");

	return 0;
}

struct rspamd_stat_cbdata {
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top;
	ucl_object_t *stat;
	struct rspamd_task *task;
	guint64 learned;
};

static gboolean
rspamd_controller_stat_fin_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;
	struct rspamd_controller_session *session;
	struct rspamd_http_connection_entry *conn_ent;
	ucl_object_t *top;

	conn_ent = cbdata->conn_ent;
	session = conn_ent->ud;
	top = cbdata->top;

	ucl_object_insert_key (top,
			ucl_object_fromint (cbdata->learned), "total_learns", 0, false);

	if (cbdata->stat) {
		ucl_object_insert_key (top, cbdata->stat, "statfiles", 0, false);
	}

	rspamd_controller_send_ucl (conn_ent, top);


	return TRUE;
}

static void
rspamd_controller_stat_cleanup_task (void *ud)
{
	struct rspamd_stat_cbdata *cbdata = ud;

	rspamd_task_free_hard (cbdata->task);
	ucl_object_unref (cbdata->top);
}

/*
 * Stat command handler:
 * request: /stat (/resetstat)
 * headers: Password
 * reply: json data
 */
static int
rspamd_controller_handle_stat_common (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg,
	gboolean do_reset)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top, *sub;
	gint i;
	guint64 spam = 0, ham = 0;
	rspamd_mempool_stat_t mem_st;
	struct rspamd_stat *stat, stat_copy;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_task *task;
	struct rspamd_stat_cbdata *cbdata;

	rspamd_mempool_stat (&mem_st);
	memcpy (&stat_copy, session->ctx->worker->srv->stat, sizeof (stat_copy));
	stat = &stat_copy;
	task = rspamd_task_new (session->ctx->worker);

	ctx = session->ctx;
	task->resolver = ctx->resolver;
	task->ev_base = ctx->ev_base;
	cbdata = rspamd_mempool_alloc0 (session->pool, sizeof (*cbdata));
	cbdata->conn_ent = conn_ent;
	cbdata->task = task;
	top = ucl_object_typed_new (UCL_OBJECT);
	cbdata->top = top;

	task->s = rspamd_session_create (session->pool,
			rspamd_controller_stat_fin_task,
			NULL,
			rspamd_controller_stat_cleanup_task,
			cbdata);
	task->fin_arg = cbdata;
	task->http_conn = rspamd_http_connection_ref (conn_ent->conn);;
	task->sock = conn_ent->conn->fd;

	ucl_object_insert_key (top, ucl_object_fromint (
			stat->messages_scanned), "scanned", 0, false);
	if (stat->messages_scanned > 0) {
		sub = ucl_object_typed_new (UCL_OBJECT);
		for (i = METRIC_ACTION_REJECT; i <= METRIC_ACTION_NOACTION; i++) {
			ucl_object_insert_key (sub,
				ucl_object_fromint (stat->actions_stat[i]),
				rspamd_action_to_str (i), 0, false);
			if (i < METRIC_ACTION_GREYLIST) {
				spam += stat->actions_stat[i];
			}
			else {
				ham += stat->actions_stat[i];
			}
			if (do_reset) {
				session->ctx->worker->srv->stat->actions_stat[i] = 0;
			}
		}
		ucl_object_insert_key (top, sub, "actions", 0, false);
	}

	ucl_object_insert_key (top, ucl_object_fromint (
			spam), "spam_count", 0, false);
	ucl_object_insert_key (top, ucl_object_fromint (
			ham),  "ham_count",	 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->connections_count), "connections", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->control_connections_count),
		"control_connections", 0, false);

	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_allocated), "pools_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.pools_freed), "pools_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.bytes_allocated), "bytes_allocated", 0,
		false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.chunks_allocated), "chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.shared_chunks_allocated),
		"shared_chunks_allocated", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (mem_st.chunks_freed), "chunks_freed", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			mem_st.oversized_chunks), "chunks_oversized", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (stat->fuzzy_hashes), "fuzzy_stored", 0, false);
	ucl_object_insert_key (top,
		ucl_object_fromint (
			stat->fuzzy_hashes_expired), "fuzzy_expired", 0, false);

	/* Fuzzy epoch statistics */
	sub = ucl_object_typed_new (UCL_ARRAY);

	for (i = RSPAMD_FUZZY_EPOCH6; i < RSPAMD_FUZZY_EPOCH_MAX; i ++) {
		ucl_array_append (sub, ucl_object_fromint (stat->fuzzy_hashes_checked[i]));
	}

	ucl_object_insert_key (top, sub, "fuzzy_checked", 0, false);
	sub = ucl_object_typed_new (UCL_ARRAY);

	for (i = RSPAMD_FUZZY_EPOCH6; i < RSPAMD_FUZZY_EPOCH_MAX; i ++) {
		ucl_array_append (sub, ucl_object_fromint (stat->fuzzy_hashes_found[i]));
	}

	ucl_object_insert_key (top, sub, "fuzzy_found", 0, false);

	if (do_reset) {
		session->ctx->srv->stat->messages_scanned = 0;
		session->ctx->srv->stat->messages_learned = 0;
		session->ctx->srv->stat->connections_count = 0;
		session->ctx->srv->stat->control_connections_count = 0;
		memset (stat->fuzzy_hashes_checked, 0,
				sizeof (stat->fuzzy_hashes_checked));
		memset (stat->fuzzy_hashes_found, 0,
				sizeof (stat->fuzzy_hashes_found));
		rspamd_mempool_stat_reset ();
	}

	/* Now write statistics for each statfile */
	rspamd_stat_statistics (task, session->ctx->cfg, &cbdata->learned,
			&cbdata->stat);
	session->task = task;
	rspamd_session_pending (task->s);

	return 0;
}

static int
rspamd_controller_handle_stat (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	return rspamd_controller_handle_stat_common (conn_ent, msg, FALSE);
}

static int
rspamd_controller_handle_statreset (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	if (!rspamd_controller_check_password (conn_ent, session, msg, TRUE)) {
		return 0;
	}

	msg_info ("<%s> reset stat",
			rspamd_inet_address_to_string (session->from_addr));
	return rspamd_controller_handle_stat_common (conn_ent, msg, TRUE);
}


/*
 * Counters command handler:
 * request: /counters
 * headers: Password
 * reply: json array of all counters
 */
static int
rspamd_controller_handle_counters (
	struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	ucl_object_t *top;
	struct symbols_cache *cache;

	if (!rspamd_controller_check_password (conn_ent, session, msg, FALSE)) {
		return 0;
	}

	cache = session->ctx->cfg->cache;

	if (cache != NULL) {
		top = rspamd_symbols_cache_counters (cache);
		rspamd_controller_send_ucl (conn_ent, top);
		ucl_object_unref (top);
	}
	else {
		rspamd_controller_send_error (conn_ent, 500, "Invalid cache");
	}

	return 0;
}

static int
rspamd_controller_handle_custom (struct rspamd_http_connection_entry *conn_ent,
	struct rspamd_http_message *msg)
{
	struct rspamd_controller_session *session = conn_ent->ud;
	struct rspamd_custom_controller_command *cmd;

	cmd = g_hash_table_lookup (session->ctx->custom_commands, msg->url->str);
	if (cmd == NULL || cmd->handler == NULL) {
		msg_err ("custom command %V has not been found", msg->url);
		rspamd_controller_send_error (conn_ent, 404, "No command associated");
		return 0;
	}

	if (!rspamd_controller_check_password (conn_ent, session, msg,
		cmd->privilleged)) {
		return 0;
	}
	if (cmd->require_message && (msg->body == NULL || msg->body->len == 0)) {
		msg_err ("got zero length body, cannot continue");
		rspamd_controller_send_error (conn_ent,
			400,
			"Empty body is not permitted");
		return 0;
	}

	return cmd->handler (conn_ent, msg, cmd->ctx);
}

static void
rspamd_controller_error_handler (struct rspamd_http_connection_entry *conn_ent,
	GError *err)
{
	msg_err ("http error occurred: %s", err->message);
}

static void
rspamd_controller_finish_handler (struct rspamd_http_connection_entry *conn_ent)
{
	struct rspamd_controller_session *session = conn_ent->ud;

	session->ctx->worker->srv->stat->control_connections_count++;
	if (session->task != NULL) {
		rspamd_session_destroy (session->task->s);
	}
	if (session->pool) {
		rspamd_mempool_delete (session->pool);
	}

	rspamd_inet_address_destroy (session->from_addr);
	g_slice_free1 (sizeof (struct rspamd_controller_session), session);
}

static void
rspamd_controller_accept_socket (gint fd, short what, void *arg)
{
	struct rspamd_worker *worker = (struct rspamd_worker *) arg;
	struct rspamd_controller_worker_ctx *ctx;
	struct rspamd_controller_session *nsession;
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

	nsession = g_slice_alloc0 (sizeof (struct rspamd_controller_session));
	nsession->pool = rspamd_mempool_new (rspamd_mempool_suggest_size (), NULL);
	nsession->ctx = ctx;

	nsession->from_addr = addr;

	rspamd_http_router_handle_socket (ctx->http, nfd, nsession);
}

static void
rspamd_controller_password_sane (const gchar *password, const gchar *type)
{
	const struct rspamd_controller_pbkdf *pbkdf = &pbkdf_list[0];
	GString *msg;
	guchar *salt, *key;
	gchar *encoded_salt, *encoded_key;

	if (password == NULL) {
		msg_warn ("%s is not set, so you should filter controller availability "
				"by using of firewall or `secure_ip` option", type);
		return;
	}

	g_assert (pbkdf != NULL);

	if (!rspamd_is_encrypted_password (password, NULL)) {
		/* Suggest encryption to a user */
		msg = g_string_new (NULL);

		rspamd_printf_gstring (msg, "your %s is not encrypted, we strongly "
				"recommend to replace it with the encrypted version: ", type);
		salt = g_alloca (pbkdf->salt_len);
		key = g_alloca (pbkdf->key_len);
		ottery_rand_bytes (salt, pbkdf->salt_len);
		/* Derive key */
		rspamd_cryptobox_pbkdf (password, strlen (password),
				salt, pbkdf->salt_len, key, pbkdf->key_len, pbkdf->rounds);

		encoded_salt = rspamd_encode_base32 (salt, pbkdf->salt_len);
		encoded_key = rspamd_encode_base32 (key, pbkdf->key_len);

		rspamd_printf_gstring (msg, "$%d$%s$%s", pbkdf->id, encoded_salt,
				encoded_key);

		msg_warn ("%v", msg);

		g_string_free (msg, TRUE);
		g_free (encoded_salt);
		g_free (encoded_key);
	}
}

gpointer
init_controller_worker (struct rspamd_config *cfg)
{
	struct rspamd_controller_worker_ctx *ctx;
	GQuark type;

	type = g_quark_try_string ("controller");

	ctx = g_malloc0 (sizeof (struct rspamd_controller_worker_ctx));

	ctx->timeout = DEFAULT_WORKER_IO_TIMEOUT;

	rspamd_rcl_register_worker_option (cfg, type, "password",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "enable_password",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, enable_password), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl",
		rspamd_rcl_parse_struct_boolean, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, use_ssl), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_cert",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_cert), 0);

	rspamd_rcl_register_worker_option (cfg, type, "ssl_key",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, ssl_key), 0);
	rspamd_rcl_register_worker_option (cfg, type, "timeout",
		rspamd_rcl_parse_struct_time, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
		timeout), RSPAMD_CL_FLAG_TIME_INTEGER);

	rspamd_rcl_register_worker_option (cfg, type, "secure_ip",
		rspamd_rcl_parse_struct_string_list, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx, secure_ip), 0);

	rspamd_rcl_register_worker_option (cfg, type, "static_dir",
		rspamd_rcl_parse_struct_string, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
		static_files_dir), 0);

	rspamd_rcl_register_worker_option (cfg, type, "keypair",
		rspamd_rcl_parse_struct_keypair, ctx,
		G_STRUCT_OFFSET (struct rspamd_controller_worker_ctx,
		key), 0);

	return ctx;
}

/*
 * Start worker process
 */
void
start_controller_worker (struct rspamd_worker *worker)
{
	struct rspamd_controller_worker_ctx *ctx = worker->ctx;
	GList *cur;
	struct module_ctx *mctx;
	GHashTableIter iter;
	gpointer key, value;
	struct rspamd_keypair_cache *cache;
	gchar *secure_ip;

	ctx->ev_base = rspamd_prepare_worker (worker,
			"controller",
			rspamd_controller_accept_socket);
	msec_to_tv (ctx->timeout, &ctx->io_tv);

	ctx->start_time = time (NULL);
	ctx->worker = worker;
	ctx->cfg = worker->srv->cfg;
	ctx->srv = worker->srv;
	ctx->custom_commands = g_hash_table_new (rspamd_strcase_hash,
			rspamd_strcase_equal);
	if (ctx->secure_ip != NULL) {
		cur = ctx->secure_ip;

		while (cur) {
			secure_ip = cur->data;

			/* Try map syntax */
			if (!rspamd_map_add (worker->srv->cfg, secure_ip,
					"Allow webui access from the specified IP",
					rspamd_radix_read, rspamd_radix_fin, (void **)&ctx->secure_map)) {
				/* Fallback to the plain IP */
				if (!radix_add_generic_iplist (secure_ip,
						&ctx->secure_map)) {
					msg_warn ("cannot load or parse ip list from '%s'",
							secure_ip);
				}
			}
			cur = g_list_next (cur);
		}
	}

	rspamd_controller_password_sane (ctx->password, "normal password");
	rspamd_controller_password_sane (ctx->enable_password, "enable password");

	/* Accept event */
	cache = rspamd_keypair_cache_new (256);
	ctx->http = rspamd_http_router_new (rspamd_controller_error_handler,
			rspamd_controller_finish_handler, &ctx->io_tv, ctx->ev_base,
			ctx->static_files_dir, cache);

	/* Add callbacks for different methods */
	rspamd_http_router_add_path (ctx->http,
				PATH_AUTH,
		rspamd_controller_handle_auth);
	rspamd_http_router_add_path (ctx->http,
			 PATH_SYMBOLS,
		rspamd_controller_handle_symbols);
	rspamd_http_router_add_path (ctx->http,
			 PATH_ACTIONS,
		rspamd_controller_handle_actions);
	rspamd_http_router_add_path (ctx->http,
				PATH_MAPS,
		rspamd_controller_handle_maps);
	rspamd_http_router_add_path (ctx->http,
			 PATH_GET_MAP,
		rspamd_controller_handle_get_map);
	rspamd_http_router_add_path (ctx->http,
		   PATH_PIE_CHART,
		rspamd_controller_handle_pie_chart);
	rspamd_http_router_add_path (ctx->http,
			 PATH_HISTORY,
		rspamd_controller_handle_history);
	rspamd_http_router_add_path (ctx->http,
		  PATH_LEARN_SPAM,
		rspamd_controller_handle_learnspam);
	rspamd_http_router_add_path (ctx->http,
		   PATH_LEARN_HAM,
		rspamd_controller_handle_learnham);
	rspamd_http_router_add_path (ctx->http,
		PATH_SAVE_ACTIONS,
		rspamd_controller_handle_saveactions);
	rspamd_http_router_add_path (ctx->http,
		PATH_SAVE_SYMBOLS,
		rspamd_controller_handle_savesymbols);
	rspamd_http_router_add_path (ctx->http,
			PATH_SAVE_MAP,
		rspamd_controller_handle_savemap);
	rspamd_http_router_add_path (ctx->http,
				PATH_SCAN,
		rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
			   PATH_CHECK,
		rspamd_controller_handle_scan);
	rspamd_http_router_add_path (ctx->http,
				PATH_STAT,
		rspamd_controller_handle_stat);
	rspamd_http_router_add_path (ctx->http,
		  PATH_STAT_RESET,
		rspamd_controller_handle_statreset);
	rspamd_http_router_add_path (ctx->http,
			PATH_COUNTERS,
		rspamd_controller_handle_counters);

	if (ctx->key) {
		rspamd_http_router_set_key (ctx->http, ctx->key);
	}

	g_hash_table_iter_init (&iter, ctx->cfg->c_modules);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		mctx = value;
		if (mctx->mod->module_attach_controller_func != NULL) {
			mctx->mod->module_attach_controller_func (mctx,
					ctx->custom_commands);
		}
	}

	g_hash_table_iter_init (&iter, ctx->custom_commands);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		rspamd_http_router_add_path (ctx->http,
			key,
			rspamd_controller_handle_custom);
	}


	ctx->resolver = dns_resolver_init (worker->srv->logger,
			ctx->ev_base,
			worker->srv->cfg);

	rspamd_upstreams_library_init (ctx->resolver->r, ctx->ev_base);
	rspamd_upstreams_library_config (worker->srv->cfg);
	/* Maps events */
	rspamd_map_watch (worker->srv->cfg, ctx->ev_base);
	rspamd_symbols_cache_start_refresh (worker->srv->cfg->cache, ctx->ev_base);
	rspamd_stat_init (worker->srv->cfg);

	event_base_loop (ctx->ev_base, 0);

	g_mime_shutdown ();
	rspamd_stat_close ();
	rspamd_http_router_free (ctx->http);
	rspamd_log_close (rspamd_main->logger);
	exit (EXIT_SUCCESS);
}
