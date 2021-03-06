/*
 * Copyright (c) 2009-2012, Vsevolod Stakhov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY AUTHOR ''AS IS'' AND ANY
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
#include "message.h"
#include "cfg_file.h"
#include "html.h"
#include "images.h"
#include "utlist.h"
#include "tokenizers/tokenizers.h"
#include "libstemmer.h"
#include "acism.h"

#include <iconv.h>

#define RECURSION_LIMIT 5
#define UTF8_CHARSET "UTF-8"
#define GTUBE_SYMBOL "GTUBE"

#define SET_PART_RAW(part) ((part)->flags &= ~RSPAMD_MIME_PART_FLAG_UTF)
#define SET_PART_UTF(part) ((part)->flags |= RSPAMD_MIME_PART_FLAG_UTF)

static ac_trie_t *gtube_trie = NULL;
static const gchar gtube_pattern[] = "XJS*C4JDBQADN1.NSBN3*2IDNEN*"
		"GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X";

static GQuark
rspamd_message_quark (void)
{
	return g_quark_from_static_string ("mime-error");
}

static void
parse_qmail_recv (rspamd_mempool_t * pool,
	gchar *line,
	struct received_header *r)
{
	gchar *s, *p, t;

	/* We are interested only with received from network headers */
	if ((p = strstr (line, "from network")) == NULL) {
		r->is_error = 2;
		return;
	}

	p += sizeof ("from network") - 1;
	while (g_ascii_isspace (*p) || *p == '[') {
		p++;
	}
	/* format is ip/host */
	s = p;
	if (*p) {
		while (g_ascii_isdigit (*++p) || *p == '.') ;
		if (*p != '/') {
			r->is_error = 1;
			return;
		}
		else {
			*p = '\0';
			r->real_ip = rspamd_mempool_strdup (pool, s);
			*p = '/';
			/* Now try to parse hostname */
			s = ++p;
			while (g_ascii_isalnum (*p) || *p == '.' || *p == '-' || *p ==
				'_') {
				p++;
			}
			t = *p;
			*p = '\0';
			r->real_hostname = rspamd_mempool_strdup (pool, s);
			*p = t;
		}
	}
}

static void
parse_recv_header (rspamd_mempool_t * pool,
	struct raw_header *rh,
	struct received_header *r)
{
	gchar *p, *s, t, **res = NULL;
	gchar *line;
	enum {
		RSPAMD_RECV_STATE_INIT = 0,
		RSPAMD_RECV_STATE_FROM,
		RSPAMD_RECV_STATE_IP_BLOCK,
		RSPAMD_RECV_STATE_BRACES_BLOCK,
		RSPAMD_RECV_STATE_BY_BLOCK,
		RSPAMD_RECV_STATE_PARSE_IP,
		RSPAMD_RECV_STATE_SKIP_SPACES,
		RSPAMD_RECV_STATE_ERROR
	}                               state = RSPAMD_RECV_STATE_INIT,
		next_state = RSPAMD_RECV_STATE_INIT;
	gboolean is_exim = FALSE;

	line = rh->decoded;
	if (line == NULL) {
		return;
	}

	g_strstrip (line);
	p = line;
	s = line;

	while (*p) {
		switch (state) {
		/* Initial state, search for from */
		case RSPAMD_RECV_STATE_INIT:
			if (*p == 'f' || *p == 'F') {
				if (g_ascii_tolower (*++p) == 'r' && g_ascii_tolower (*++p) ==
					'o' && g_ascii_tolower (*++p) == 'm') {
					p++;
					state = RSPAMD_RECV_STATE_SKIP_SPACES;
					next_state = RSPAMD_RECV_STATE_FROM;
				}
			}
			else if (g_ascii_tolower (*p) == 'b' &&
				g_ascii_tolower (*(p + 1)) == 'y') {
				state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			else {
				/* This can be qmail header, parse it separately */
				parse_qmail_recv (pool, line, r);
				return;
			}
			break;
		/* Read hostname */
		case RSPAMD_RECV_STATE_FROM:
			if (*p == '[') {
				/* This should be IP address */
				res = &r->from_ip;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
				s = ++p;
			}
			else if (g_ascii_isalnum (*p) || *p == '.' || *p == '-' || *p ==
				'_') {
				p++;
			}
			else {
				t = *p;
				*p = '\0';
				r->from_hostname = rspamd_mempool_strdup (pool, s);
				*p = t;
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			break;
		/* Try to extract additional info */
		case RSPAMD_RECV_STATE_IP_BLOCK:
			/* Try to extract ip or () info or by */
			if (g_ascii_tolower (*p) == 'b' && g_ascii_tolower (*(p + 1)) ==
				'y') {
				p += 2;
				/* Skip spaces after by */
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_BY_BLOCK;
			}
			else if (*p == '(') {
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
				p++;
			}
			else if (*p == '[') {
				/* Got ip before '(' so extract it */
				s = ++p;
				res = &r->from_ip;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				next_state = RSPAMD_RECV_STATE_IP_BLOCK;
			}
			else {
				p++;
			}
			break;
		/* We are in () block. Here can be found real hostname and real ip, this is written by some MTA */
		case RSPAMD_RECV_STATE_BRACES_BLOCK:
			/* End of block */
			if (g_ascii_isalnum (*p) || *p == '.' || *p == '-' ||
				*p == '_' || *p == ':') {
				p++;
			}
			else if (*p == '[') {
				s = ++p;
				state = RSPAMD_RECV_STATE_PARSE_IP;
				res = &r->real_ip;
				next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
			}
			else {
				if (p > s) {
					/* Got some real hostname */
					/* check whether it is helo or p is not space symbol */
					if (!g_ascii_isspace (*p) || *(p + 1) != '[') {
						/* Exim style ([ip]:port helo=hostname) */
						if (*s == ':' && (g_ascii_isspace (*p) || *p == ')')) {
							/* Ip ending */
							is_exim = TRUE;
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else if (p - s == 4 && memcmp (s, "helo=", 5) == 0) {
							p++;
							is_exim = TRUE;
							if (r->real_hostname == NULL && r->from_hostname !=
								NULL) {
								r->real_hostname = r->from_hostname;
							}
							s = p;
							while (*p != ')' && !g_ascii_isspace (*p) && *p !=
								'\0') {
								p++;
							}
							if (p > s) {
								r->from_hostname = rspamd_mempool_alloc (pool,
										p - s + 1);
								rspamd_strlcpy (r->from_hostname, s, p - s + 1);
							}
						}
						else if (p - s == 4 && memcmp (s, "port=", 5) == 0) {
							p++;
							is_exim = TRUE;
							while (g_ascii_isdigit (*p)) {
								p++;
							}
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else if (*p == '=' && is_exim) {
							/* Just skip unknown pairs */
							p++;
							while (!g_ascii_isspace (*p) && *p != ')' && *p !=
								'\0') {
								p++;
							}
							state = RSPAMD_RECV_STATE_SKIP_SPACES;
							next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						}
						else {
							/* skip all  */
							while (*p++ != ')' && *p != '\0') ;
							state = RSPAMD_RECV_STATE_IP_BLOCK;
						}
					}
					else {
						/* Postfix style (hostname [ip]) */
						t = *p;
						*p = '\0';
						r->real_hostname = rspamd_mempool_strdup (pool, s);
						*p = t;
						/* Now parse ip */
						p += 2;
						s = p;
						res = &r->real_ip;
						state = RSPAMD_RECV_STATE_PARSE_IP;
						next_state = RSPAMD_RECV_STATE_BRACES_BLOCK;
						continue;
					}
					if (*p == ')') {
						p++;
						state = RSPAMD_RECV_STATE_SKIP_SPACES;
						next_state = RSPAMD_RECV_STATE_IP_BLOCK;
					}
				}
				else if (*p == ')') {
					p++;
					state = RSPAMD_RECV_STATE_SKIP_SPACES;
					next_state = RSPAMD_RECV_STATE_IP_BLOCK;
				}
				else {
					r->is_error = 1;
					return;
				}
			}
			break;
		/* Got by word */
		case RSPAMD_RECV_STATE_BY_BLOCK:
			/* Here can be only hostname */
			if ((g_ascii_isalnum (*p) || *p == '.' || *p == '-'
				|| *p == '_') && p[1] != '\0') {
				p++;
			}
			else {
				/* We got something like hostname */
				if (p[1] != '\0') {
					t = *p;
					*p = '\0';
					r->by_hostname = rspamd_mempool_strdup (pool, s);
					*p = t;
				}
				else {
					r->by_hostname = rspamd_mempool_strdup (pool, s);
				}
				/* Now end of parsing */
				if (is_exim) {
					/* Adjust for exim received */
					if (r->real_ip == NULL && r->from_ip != NULL) {
						r->real_ip = r->from_ip;
					}
					else if (r->from_ip == NULL && r->real_ip != NULL) {
						r->from_ip = r->real_ip;
						if (r->real_hostname == NULL && r->from_hostname !=
							NULL) {
							r->real_hostname = r->from_hostname;
						}
					}
				}
				return;
			}
			break;

		/* Extract ip */
		case RSPAMD_RECV_STATE_PARSE_IP:
			while (g_ascii_isxdigit (*p) || *p == '.' || *p == ':') {
				p++;
			}
			if (*p != ']') {
				/* Not an ip in fact */
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
				p++;
			}
			else {
				*p = '\0';
				*res = rspamd_mempool_strdup (pool, s);
				*p = ']';
				p++;
				state = RSPAMD_RECV_STATE_SKIP_SPACES;
			}
			break;

		/* Skip spaces */
		case RSPAMD_RECV_STATE_SKIP_SPACES:
			if (!g_ascii_isspace (*p)) {
				state = next_state;
				s = p;
			}
			else {
				p++;
			}
			break;
		default:
			r->is_error = 1;
			return;
			break;
		}
	}

	r->is_error = 1;
	return;
}

static void
append_raw_header (GHashTable *target, struct raw_header *rh)
{
	struct raw_header *lp;

	rh->next = NULL;
	rh->prev = rh;
	if ((lp =
			g_hash_table_lookup (target, rh->name)) != NULL) {
		DL_APPEND (lp, rh);
	}
	else {
		g_hash_table_insert (target, rh->name, rh);
	}
	msg_debug ("add raw header %s: %s", rh->name, rh->value);
}

/* Convert raw headers to a list of struct raw_header * */
static void
process_raw_headers (struct rspamd_task *task, GHashTable *target,
		const gchar *in, gsize len)
{
	struct raw_header *new = NULL;
	const gchar *p, *c, *end;
	gchar *tmp, *tp;
	gint state = 0, l, next_state = 100, err_state = 100, t_state;
	gboolean valid_folding = FALSE;

	p = in;
	end = p + len;
	c = p;

	while (p <= end) {
		/* FSM for processing headers */
		switch (state) {
		case 0:
			/* Begin processing headers */
			if (!g_ascii_isalpha (*p)) {
				/* We have some garbage at the beginning of headers, skip this line */
				state = 100;
				next_state = 0;
			}
			else {
				state = 1;
				c = p;
			}
			break;
		case 1:
			/* We got something like header's name */
			if (*p == ':') {
				new =
					rspamd_mempool_alloc0 (task->task_pool,
						sizeof (struct raw_header));
				new->prev = new;
				l = p - c;
				tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
				rspamd_strlcpy (tmp, c, l + 1);
				new->name = tmp;
				new->empty_separator = TRUE;
				p++;
				state = 2;
				c = p;
			}
			else if (g_ascii_isspace (*p)) {
				/* Not header but some garbage */
				state = 100;
				next_state = 0;
			}
			else {
				p++;
			}
			break;
		case 2:
			/* We got header's name, so skip any \t or spaces */
			if (*p == '\t') {
				new->tab_separated = TRUE;
				new->empty_separator = FALSE;
				p++;
			}
			else if (*p == ' ') {
				new->empty_separator = FALSE;
				p++;
			}
			else if (*p == '\n' || *p == '\r') {
				/* Process folding */
				state = 99;
				l = p - c;
				if (l > 0) {
					tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
					rspamd_strlcpy (tmp, c, l + 1);
					new->separator = tmp;
				}
				next_state = 3;
				err_state = 5;
				c = p;
			}
			else {
				/* Process value */
				l = p - c;
				if (l >= 0) {
					tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
					rspamd_strlcpy (tmp, c, l + 1);
					new->separator = tmp;
				}
				c = p;
				state = 3;
			}
			break;
		case 3:
			if (*p == '\r' || *p == '\n') {
				/* Hold folding */
				state = 99;
				next_state = 3;
				err_state = 4;
			}
			else if (p + 1 == end) {
				state = 4;
			}
			else {
				p++;
			}
			break;
		case 4:
			/* Copy header's value */
			l = p - c;
			tmp = rspamd_mempool_alloc (task->task_pool, l + 1);
			tp = tmp;
			t_state = 0;
			while (l--) {
				if (t_state == 0) {
					/* Before folding */
					if (*c == '\n' || *c == '\r') {
						t_state = 1;
						c++;
						*tp++ = ' ';
					}
					else {
						*tp++ = *c++;
					}
				}
				else if (t_state == 1) {
					/* Inside folding */
					if (g_ascii_isspace (*c)) {
						c++;
					}
					else {
						t_state = 0;
						*tp++ = *c++;
					}
				}
			}
			/* Strip last space that can be added by \r\n parsing */
			if (*(tp - 1) == ' ') {
				tp--;
			}

			*tp = '\0';
			new->value = tmp;
			new->decoded = g_mime_utils_header_decode_text (new->value);
			rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t)g_free, new->decoded);
			append_raw_header (target, new);
			state = 0;
			break;
		case 5:
			/* Header has only name, no value */
			new->value = "";
			new->decoded = NULL;
			append_raw_header (target, new);
			state = 0;
			break;
		case 99:
			/* Folding state */
			if (p + 1 == end) {
				state = err_state;
			}
			else {
				if (*p == '\r' || *p == '\n') {
					p++;
					valid_folding = FALSE;
				}
				else if (*p == '\t' || *p == ' ') {
					/* Valid folding */
					p++;
					valid_folding = TRUE;
				}
				else {
					if (valid_folding) {
						debug_task ("go to state: %d->%d", state, next_state);
						state = next_state;
					}
					else {
						/* Fall back */
						debug_task ("go to state: %d->%d", state, err_state);
						state = err_state;
					}
				}
			}
			break;
		case 100:
			/* Fail state, skip line */
			if (*p == '\r') {
				if (*(p + 1) == '\n') {
					p++;
				}
				p++;
				state = next_state;
			}
			else if (*p == '\n') {
				if (*(p + 1) == '\r') {
					p++;
				}
				p++;
				state = next_state;
			}
			else if (p + 1 == end) {
				state = next_state;
				p++;
			}
			else {
				p++;
			}
			break;
		}
	}
}

static void
free_byte_array_callback (void *pointer)
{
	GByteArray *arr = (GByteArray *) pointer;
	g_byte_array_free (arr, TRUE);
}

static gboolean
charset_validate (rspamd_mempool_t *pool, const gchar *in, gchar **out)
{
	/*
	 * This is a simple routine to validate input charset
	 * we just check that charset starts with alphanumeric and ends
	 * with alphanumeric
	 */
	const gchar *begin, *end;
	gboolean changed = FALSE, to_uppercase = FALSE;

	begin = in;

	while (!g_ascii_isalnum (*begin)) {
		begin ++;
		changed = TRUE;
	}
	if (!g_ascii_islower(*begin)) {
		changed = TRUE;
		to_uppercase = TRUE;
	}
	end = begin + strlen (begin) - 1;
	while (!g_ascii_isalnum (*end)) {
		end --;
		changed = TRUE;
	}

	if (!changed) {
		*out = (gchar *)in;
	}
	else {
		*out = rspamd_mempool_alloc (pool, end - begin + 2);
		if (to_uppercase) {
			gchar *o = *out;

			while (begin != end + 1) {
				if (g_ascii_islower (*begin)) {
					*o++ = g_ascii_toupper (*begin ++);
				}
				else {
					*o++ = *begin++;
				}
			}
			*o = '\0';
		}
		else {
			rspamd_strlcpy (*out, begin, end - begin + 2);
		}
	}

	return TRUE;
}

static GQuark
converter_error_quark (void)
{
	return g_quark_from_static_string ("conversion error");
}

static gchar *
rspamd_text_to_utf8 (struct rspamd_task *task,
		gchar *input, gsize len, const gchar *in_enc,
		gsize *olen, GError **err)
{
	gchar *res, *s, *d;
	gsize outlen;
	iconv_t ic;
	gsize processed, ret;

	ic = iconv_open (UTF8_CHARSET, in_enc);

	if (ic == (iconv_t)-1) {
		g_set_error (err, converter_error_quark(), EINVAL,
				"cannot open iconv for: %s", in_enc);
		return NULL;
	}

	/* For the most of charsets utf8 notation is larger than native one */
	outlen = len * 2 + 1;

	res = rspamd_mempool_alloc (task->task_pool, outlen);
	s = input;
	d = res;
	processed = outlen - 1;

	while (len > 0 && processed > 0) {
		ret = iconv (ic, &s, &len, &d, &processed);
		if (ret == (gsize)-1) {
			switch (errno) {
			case E2BIG:
				g_set_error (err, converter_error_quark(), EINVAL,
						"output of size %zd is not enough to handle "
						"converison of %zd bytes", outlen, len);
				iconv_close (ic);
				return NULL;
			case EILSEQ:
			case EINVAL:
				/* Ignore bad characters */
				if (processed > 0 && len > 0) {
					*d++ = '?';
					s++;
					len --;
					processed --;
				}
				break;
			}
		}
		else if (ret == 0) {
			break;
		}
	}

	*d = '\0';
	*olen = d - res;

	iconv_close (ic);

	return res;
}


static GByteArray *
convert_text_to_utf (struct rspamd_task *task,
	GByteArray * part_content,
	GMimeContentType * type,
	struct mime_text_part *text_part)
{
	GError *err = NULL;
	gsize write_bytes;
	const gchar *charset;
	gchar *res_str, *ocharset;
	GByteArray *result_array;

	if (task->cfg->raw_mode) {
		SET_PART_RAW (text_part);
		return part_content;
	}

	if ((charset =
		g_mime_content_type_get_parameter (type, "charset")) == NULL) {
		SET_PART_RAW (text_part);
		return part_content;
	}
	if (!charset_validate (task->task_pool, charset, &ocharset)) {
		msg_info (
			"<%s>: has invalid charset",
			task->message_id);
		SET_PART_RAW (text_part);
		return part_content;
	}

	if (g_ascii_strcasecmp (ocharset,
		"utf-8") == 0 || g_ascii_strcasecmp (ocharset, "utf8") == 0) {
		if (g_utf8_validate (part_content->data, part_content->len, NULL)) {
			SET_PART_UTF (text_part);
			return part_content;
		}
		else {
			msg_info (
				"<%s>: contains invalid utf8 characters, assume it as raw",
				task->message_id);
			SET_PART_RAW (text_part);
			return part_content;
		}
	}
	else {
		res_str = rspamd_text_to_utf8 (task, part_content->data,
				part_content->len,
				ocharset,
				&write_bytes,
				&err);
		if (res_str == NULL) {
			msg_warn ("<%s>: cannot convert from %s to utf8: %s",
					task->message_id,
					ocharset,
					err ? err->message : "unknown problem");
			SET_PART_RAW (text_part);
			g_error_free (err);
			return part_content;
		}
	}

	result_array = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	result_array->data = res_str;
	result_array->len = write_bytes;
	SET_PART_UTF (text_part);

	return result_array;
}

struct language_match {
	const char *code;
	const char *name;
	GUnicodeScript script;
};

static int
language_elts_cmp (const void *a, const void *b)
{
	GUnicodeScript sc = *(const GUnicodeScript *)a;
	const struct language_match *bb = (const struct language_match *)b;

	return (sc - bb->script);
}

static void
detect_text_language (struct mime_text_part *part)
{
	/* Keep sorted */
	static const struct language_match language_codes[] = {
			{ "", "english", G_UNICODE_SCRIPT_COMMON },
			{ "", "", G_UNICODE_SCRIPT_INHERITED },
			{ "ar", "arabic", G_UNICODE_SCRIPT_ARABIC },
			{ "hy", "armenian", G_UNICODE_SCRIPT_ARMENIAN },
			{ "bn", "chineese", G_UNICODE_SCRIPT_BENGALI },
			{ "", "", G_UNICODE_SCRIPT_BOPOMOFO },
			{ "chr", "", G_UNICODE_SCRIPT_CHEROKEE },
			{ "cop", "",  G_UNICODE_SCRIPT_COPTIC  },
			{ "ru", "russian",  G_UNICODE_SCRIPT_CYRILLIC },
			/* Deseret was used to write English */
			{ "", "",  G_UNICODE_SCRIPT_DESERET },
			{ "hi", "",  G_UNICODE_SCRIPT_DEVANAGARI },
			{ "am", "",  G_UNICODE_SCRIPT_ETHIOPIC },
			{ "ka", "",  G_UNICODE_SCRIPT_GEORGIAN },
			{ "", "",  G_UNICODE_SCRIPT_GOTHIC },
			{ "el", "greek",  G_UNICODE_SCRIPT_GREEK },
			{ "gu", "",  G_UNICODE_SCRIPT_GUJARATI },
			{ "pa", "",  G_UNICODE_SCRIPT_GURMUKHI },
			{ "han", "chineese",  G_UNICODE_SCRIPT_HAN },
			{ "ko", "",  G_UNICODE_SCRIPT_HANGUL },
			{ "he", "hebrew",  G_UNICODE_SCRIPT_HEBREW },
			{ "ja", "",  G_UNICODE_SCRIPT_HIRAGANA },
			{ "kn", "",  G_UNICODE_SCRIPT_KANNADA },
			{ "ja", "",  G_UNICODE_SCRIPT_KATAKANA },
			{ "km", "",  G_UNICODE_SCRIPT_KHMER },
			{ "lo", "",  G_UNICODE_SCRIPT_LAO },
			{ "en", "english",  G_UNICODE_SCRIPT_LATIN },
			{ "ml", "",  G_UNICODE_SCRIPT_MALAYALAM },
			{ "mn", "",  G_UNICODE_SCRIPT_MONGOLIAN },
			{ "my", "",  G_UNICODE_SCRIPT_MYANMAR },
			/* Ogham was used to write old Irish */
			{ "", "",  G_UNICODE_SCRIPT_OGHAM },
			{ "", "",  G_UNICODE_SCRIPT_OLD_ITALIC },
			{ "or", "",  G_UNICODE_SCRIPT_ORIYA },
			{ "", "",  G_UNICODE_SCRIPT_RUNIC },
			{ "si", "",  G_UNICODE_SCRIPT_SINHALA },
			{ "syr", "",  G_UNICODE_SCRIPT_SYRIAC },
			{ "ta", "",  G_UNICODE_SCRIPT_TAMIL },
			{ "te", "",  G_UNICODE_SCRIPT_TELUGU },
			{ "dv", "",  G_UNICODE_SCRIPT_THAANA },
			{ "th", "",  G_UNICODE_SCRIPT_THAI },
			{ "bo", "",  G_UNICODE_SCRIPT_TIBETAN },
			{ "iu", "",  G_UNICODE_SCRIPT_CANADIAN_ABORIGINAL },
			{ "", "",  G_UNICODE_SCRIPT_YI },
			{ "tl", "",  G_UNICODE_SCRIPT_TAGALOG },
			/* Phillipino languages/scripts */
			{ "hnn", "",  G_UNICODE_SCRIPT_HANUNOO },
			{ "bku", "",  G_UNICODE_SCRIPT_BUHID },
			{ "tbw", "",  G_UNICODE_SCRIPT_TAGBANWA },

			{ "", "",  G_UNICODE_SCRIPT_BRAILLE },
			{ "", "",  G_UNICODE_SCRIPT_CYPRIOT },
			{ "", "",  G_UNICODE_SCRIPT_LIMBU },
			/* Used for Somali (so) in the past */
			{ "", "",  G_UNICODE_SCRIPT_OSMANYA },
			/* The Shavian alphabet was designed for English */
			{ "", "",  G_UNICODE_SCRIPT_SHAVIAN },
			{ "", "",  G_UNICODE_SCRIPT_LINEAR_B },
			{ "", "",  G_UNICODE_SCRIPT_TAI_LE },
			{ "uga", "",  G_UNICODE_SCRIPT_UGARITIC },
			{ "", "",  G_UNICODE_SCRIPT_NEW_TAI_LUE },
			{ "bug", "",  G_UNICODE_SCRIPT_BUGINESE },
			{ "", "",  G_UNICODE_SCRIPT_GLAGOLITIC },
			/* Used for for Berber (ber), but Arabic script is more common */
			{ "", "",  G_UNICODE_SCRIPT_TIFINAGH },
			{ "syl", "",  G_UNICODE_SCRIPT_SYLOTI_NAGRI },
			{ "peo", "",  G_UNICODE_SCRIPT_OLD_PERSIAN },
			{ "", "",  G_UNICODE_SCRIPT_KHAROSHTHI },
			{ "", "",  G_UNICODE_SCRIPT_UNKNOWN },
			{ "", "",  G_UNICODE_SCRIPT_BALINESE },
			{ "", "",  G_UNICODE_SCRIPT_CUNEIFORM },
			{ "", "",  G_UNICODE_SCRIPT_PHOENICIAN },
			{ "", "",  G_UNICODE_SCRIPT_PHAGS_PA },
			{ "nqo", "", G_UNICODE_SCRIPT_NKO }
	};
	const struct language_match *lm;
	const int max_chars = 32;

	if (part != NULL) {
		if (IS_PART_UTF (part)) {
			/* Try to detect encoding by several symbols */
			const gchar *p, *pp;
			gunichar c;
			gint32 remain = part->content->len, max = 0, processed = 0;
			gint32 scripts[G_N_ELEMENTS (language_codes)];
			GUnicodeScript scc, sel = G_UNICODE_SCRIPT_COMMON;

			p = part->content->data;
			memset (scripts, 0, sizeof (scripts));

			while (remain > 0 && processed < max_chars) {
				c = g_utf8_get_char_validated (p, remain);
				if (c == (gunichar) -2 || c == (gunichar) -1) {
					break;
				}
				if (g_unichar_isalpha (c)) {
					scc = g_unichar_get_script (c);
					if (scc < (gint)G_N_ELEMENTS (scripts)) {
						scripts[scc]++;
					}
					processed ++;
				}
				pp = g_utf8_next_char (p);
				remain -= pp - p;
				p = pp;
			}
			for (remain = 0; remain < (gint)G_N_ELEMENTS (scripts); remain++) {
				if (scripts[remain] > max) {
					max = scripts[remain];
					sel = remain;
				}
			}
			part->script = sel;
			lm = bsearch (&sel, language_codes, G_N_ELEMENTS (language_codes),
					sizeof (language_codes[0]), &language_elts_cmp);

			if (lm != NULL) {
				part->lang_code = lm->code;
				part->language = lm->name;
			}
		}
	}
}

static void
rspamd_normalize_text_part (struct rspamd_task *task,
		struct mime_text_part *part)
{
	struct sb_stemmer *stem = NULL;
	rspamd_fstring_t *w;
	const guchar *r;
	gchar *temp_word;
	guint i, nlen;
	GArray *tmp;

	if (part->language && part->language[0] != '\0' && IS_PART_UTF (part)) {
		stem = sb_stemmer_new (part->language, "UTF_8");
		if (stem == NULL) {
			msg_info ("<%s> cannot create lemmatizer for %s language",
				task->message_id, part->language);
		}
	}

	/* Ugly workaround */
	tmp = rspamd_tokenize_text (part->content->data,
			part->content->len, IS_PART_UTF (part), task->cfg->min_word_len,
			part->urls_offset, FALSE,
			!(part->flags & RSPAMD_MIME_PART_FLAG_HTML));

	if (tmp) {
		for (i = 0; i < tmp->len; i ++) {
			w = &g_array_index (tmp, rspamd_fstring_t, i);
			if (stem) {
				r = sb_stemmer_stem (stem, w->begin, w->len);
			}

			if (w->len > 0 && !(w->len == 6 && memcmp (w->begin, "!!EX!!", 6) == 0)) {
				if (stem != NULL && r != NULL) {
					nlen = strlen (r);
					nlen = MIN (nlen, w->len);
					w->begin = rspamd_mempool_alloc (task->task_pool, nlen);
					memcpy (w->begin, r, nlen);
					w->len = nlen;
				}
				else {
					temp_word = w->begin;
					w->begin = rspamd_mempool_alloc (task->task_pool, w->len);
					memcpy (w->begin, temp_word, w->len);

					if (IS_PART_UTF (part)) {
						rspamd_str_lc_utf8 (w->begin, w->len);
					}
					else {
						rspamd_str_lc (w->begin, w->len);
					}
				}
			}
		}
		part->normalized_words = tmp;
	}

	if (stem != NULL) {
		sb_stemmer_delete (stem);
	}
}

#define MIN3(a, b, c) ((a) < (b) ? ((a) < (c) ? (a) : (c)) : ((b) < (c) ? (b) : (c)))

static gint
rspamd_words_levenshtein_distance (GArray *w1, GArray *w2)
{
	guint s1len, s2len, x, y, lastdiag, olddiag;
	guint *column;
	rspamd_fstring_t *s1, *s2;
	gint eq;
	static const guint max_words = 8192;

	s1len = w1->len;
	s2len = w2->len;

	if (s1len > max_words) {
		msg_err ("cannot compare parts with more than %ud words: %ud",
				max_words, s1len);
		return 0;
	}

	column = g_alloca ((s1len + 1) * sizeof (guint));

	for (y = 1; y <= s1len; y++) {
		column[y] = y;
	}

	for (x = 1; x <= s2len; x++) {
		column[0] = x;

		for (y = 1, lastdiag = x - 1; y <= s1len; y++) {
			olddiag = column[y];
			s1 = &g_array_index (w1, rspamd_fstring_t, y - 1);
			s2 = &g_array_index (w2, rspamd_fstring_t, x - 1);
			eq = rspamd_fstring_equal (s1, s2) ? 0 : 1;
			column[y] = MIN3 (column[y] + 1, column[y - 1] + 1,
					lastdiag + (eq));
			lastdiag = olddiag;
		}
	}

	return column[s1len];
}

static int
rspamd_gtube_cb (int strnum, int textpos, void *context)
{
	return TRUE;
}

static gboolean
rspamd_check_gtube (struct rspamd_task *task, struct mime_text_part *part)
{
	static ac_trie_pat_t pat[1] = {
		{
			.ptr = gtube_pattern,
			.len = sizeof (gtube_pattern) - 1
		}
	};
	gint state = 0;

	g_assert (part != NULL);

	if (gtube_trie == NULL) {
		gtube_trie = acism_create (pat, G_N_ELEMENTS (pat));
	}

	if (part->content && part->content->len > sizeof (gtube_pattern)) {
		if (acism_lookup (gtube_trie, part->content->data, part->content->len,
				rspamd_gtube_cb, NULL, &state, FALSE)) {
			task->flags |= RSPAMD_TASK_FLAG_SKIP;
			task->flags |= RSPAMD_TASK_FLAG_GTUBE;
			msg_info ("<%s>: gtube pattern has been found in part of length %ud",
					task->message_id, part->content->len);

			return TRUE;
		}
	}

	return FALSE;
}

static void
process_text_part (struct rspamd_task *task,
	GByteArray *part_content,
	GMimeContentType *type,
	struct mime_part *mime_part,
	GMimeObject *parent,
	gboolean is_empty)
{
	struct mime_text_part *text_part;
	const gchar *cd, *p, *c;
	guint remain;

	/* Skip attachements */
#ifndef GMIME24
	cd = g_mime_part_get_content_disposition (GMIME_PART (mime_part->mime));
	if (cd &&
		g_ascii_strcasecmp (cd,
		"attachment") == 0 && !task->cfg->check_text_attachements) {
		debug_task ("skip attachments for checking as text parts");
		return;
	}
#else
	cd = g_mime_object_get_disposition (GMIME_OBJECT (mime_part->mime));
	if (cd &&
		g_ascii_strcasecmp (cd,
		GMIME_DISPOSITION_ATTACHMENT) == 0 &&
		!task->cfg->check_text_attachements) {
		debug_task ("skip attachments for checking as text parts");
		return;
	}
#endif

	if (g_mime_content_type_is_type (type, "text",
		"html") || g_mime_content_type_is_type (type, "text", "xhtml")) {

		text_part =
			rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct mime_text_part));
		text_part->flags |= RSPAMD_MIME_PART_FLAG_HTML;
		if (is_empty) {
			text_part->flags |= RSPAMD_MIME_PART_FLAG_EMPTY;
			text_part->orig = NULL;
			text_part->content = NULL;
			g_ptr_array_add (task->text_parts, text_part);
			return;
		}
		text_part->orig = part_content;
		part_content = convert_text_to_utf (task,
				text_part->orig,
				type,
				text_part);
		text_part->html = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (*text_part->html));
		text_part->parent = parent;
		text_part->mime_part = mime_part;

		text_part->flags |= RSPAMD_MIME_PART_FLAG_BALANCED;
		text_part->content = rspamd_html_process_part_full (
				task->task_pool,
				text_part->html,
				part_content,
				&text_part->urls_offset,
				task->urls,
				task->emails);

		if (text_part->content->len == 0) {
			text_part->flags |= RSPAMD_MIME_PART_FLAG_EMPTY;
		}

		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) free_byte_array_callback,
			text_part->content);
		g_ptr_array_add (task->text_parts, text_part);
	}
	else if (g_mime_content_type_is_type (type, "text", "*")) {

		text_part =
			rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct mime_text_part));
		text_part->parent = parent;
		text_part->mime_part = mime_part;

		if (is_empty) {
			text_part->flags |= RSPAMD_MIME_PART_FLAG_EMPTY;
			text_part->orig = NULL;
			text_part->content = NULL;
			g_ptr_array_add (task->text_parts, text_part);
			return;
		}

		text_part->content = convert_text_to_utf (task,
				part_content,
				type,
				text_part);
		text_part->orig = part_content;
		rspamd_url_text_extract (task->task_pool, task, text_part, FALSE);
		g_ptr_array_add (task->text_parts, text_part);
	}
	else {
		return;
	}

	if (rspamd_check_gtube (task, text_part)) {
		struct metric_result *mres;

		mres = rspamd_create_metric_result (task, DEFAULT_METRIC);

		if (mres != NULL) {
			mres->score = mres->metric->actions[METRIC_ACTION_REJECT].score;
			mres->action = METRIC_ACTION_REJECT;
		}

		task->pre_result.action = METRIC_ACTION_REJECT;
		task->pre_result.str = "Gtube pattern";
		rspamd_task_insert_result (task, GTUBE_SYMBOL, 0, NULL);

		return;
	}

	/* Post process part */
	detect_text_language (text_part);
	text_part->words = rspamd_tokenize_text (text_part->content->data,
			text_part->content->len, IS_PART_UTF (text_part), task->cfg->min_word_len,
			text_part->urls_offset, FALSE,
			!(text_part->flags & RSPAMD_MIME_PART_FLAG_HTML));
	rspamd_normalize_text_part (task, text_part);

	/* Calculate number of lines */
	p = text_part->content->data;
	remain = text_part->content->len;
	c = p;

	while (p != NULL && remain > 0) {
		p = memchr (c, '\n', remain);

		if (p != NULL) {
			text_part->nlines ++;
			remain -= p - c + 1;
			c = p + 1;
		}
	}
}

struct mime_foreach_data {
	struct rspamd_task *task;
	guint parser_recursion;
	GMimeObject *parent;
};

#ifdef GMIME24
static void
mime_foreach_callback (GMimeObject * parent,
	GMimeObject * part,
	gpointer user_data)
#else
static void
mime_foreach_callback (GMimeObject * part, gpointer user_data)
#endif
{
	struct mime_foreach_data *md = user_data;
	struct rspamd_task *task;
	struct mime_part *mime_part;
	GMimeContentType *type;
	GMimeDataWrapper *wrapper;
	GMimeStream *part_stream;
	GByteArray *part_content;
	gchar *hdrs;

	task = md->task;
	/* 'part' points to the current part node that g_mime_message_foreach_part() is iterating over */

	/* find out what class 'part' is... */
	if (GMIME_IS_MESSAGE_PART (part)) {
		/* message/rfc822 or message/news */
		GMimeMessage *message;

		/* g_mime_message_foreach_part() won't descend into
		   child message parts, so if we want to count any
		   subparts of this child message, we'll have to call
		   g_mime_message_foreach_part() again here. */

		message = g_mime_message_part_get_message ((GMimeMessagePart *) part);
		if (md->parser_recursion++ < RECURSION_LIMIT) {
#ifdef GMIME24
			g_mime_message_foreach (message, mime_foreach_callback, md);
#else
			g_mime_message_foreach_part (message, mime_foreach_callback, md);
#endif
		}
		else {
			msg_err ("too deep mime recursion detected: %d", md->parser_recursion);
			return;
		}
#ifndef GMIME24
		g_object_unref (message);
#endif
	}
	else if (GMIME_IS_MESSAGE_PARTIAL (part)) {
		/* message/partial */

		/* this is an incomplete message part, probably a
		   large message that the sender has broken into
		   smaller parts and is sending us bit by bit. we
		   could save some info about it so that we could
		   piece this back together again once we get all the
		   parts? */
	}
	else if (GMIME_IS_MULTIPART (part)) {
		/* multipart/mixed, multipart/alternative, multipart/related, multipart/signed, multipart/encrypted, etc... */
#ifndef GMIME24
		debug_task ("detected multipart part");
		/* we'll get to finding out if this is a signed/encrypted multipart later... */
		if (task->parser_recursion++ < RECURSION_LIMIT) {
			g_mime_multipart_foreach ((GMimeMultipart *) part,
				mime_foreach_callback,
				md);
		}
		else {
			msg_err ("endless recursion detected: %d", task->parser_recursion);
			return;
		}
#endif
		type = (GMimeContentType *) g_mime_object_get_content_type (GMIME_OBJECT (
				part));
		mime_part = rspamd_mempool_alloc0 (task->task_pool,
				sizeof (struct mime_part));

		hdrs = g_mime_object_get_headers (GMIME_OBJECT (part));
		mime_part->raw_headers = g_hash_table_new (rspamd_strcase_hash,
				rspamd_strcase_equal);
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_hash_table_destroy,
				mime_part->raw_headers);
		if (hdrs != NULL) {
			process_raw_headers (task, mime_part->raw_headers,
					hdrs, strlen (hdrs));
			g_free (hdrs);
		}

		mime_part->type = type;
		/* XXX: we don't need it, but it's sometimes dereferenced */
		mime_part->content = g_byte_array_new ();
		mime_part->parent = md->parent;
		mime_part->filename = NULL;
		mime_part->mime = part;

		debug_task ("found part with content-type: %s/%s",
				type->type,
				type->subtype);
		g_ptr_array_add (task->parts, mime_part);

		md->parent = part;
	}
	else if (GMIME_IS_PART (part)) {
		/* a normal leaf part, could be text/plain or image/jpeg etc */
#ifdef GMIME24
		type = (GMimeContentType *) g_mime_object_get_content_type (GMIME_OBJECT (
					part));
#else
		type =
			(GMimeContentType *) g_mime_part_get_content_type (GMIME_PART (part));
#endif

		if (type == NULL) {
			msg_warn ("type of part is unknown, assume text/plain");
			type = g_mime_content_type_new ("text", "plain");
#ifdef GMIME24
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,				 type);
#else
			rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_mime_content_type_destroy, type);
#endif
		}
		wrapper = g_mime_part_get_content_object (GMIME_PART (part));
#ifdef GMIME24
		if (wrapper != NULL && GMIME_IS_DATA_WRAPPER (wrapper)) {
#else
		if (wrapper != NULL) {
#endif
			part_stream = g_mime_stream_mem_new ();
			if (g_mime_data_wrapper_write_to_stream (wrapper,
				part_stream) != -1) {

				g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (
						part_stream), FALSE);
				part_content = g_mime_stream_mem_get_byte_array (GMIME_STREAM_MEM (
							part_stream));
				g_object_unref (part_stream);
				mime_part =
					rspamd_mempool_alloc (task->task_pool,
						sizeof (struct mime_part));

				hdrs = g_mime_object_get_headers (GMIME_OBJECT (part));
				mime_part->raw_headers = g_hash_table_new (rspamd_strcase_hash,
						rspamd_strcase_equal);
				rspamd_mempool_add_destructor (task->task_pool,
					(rspamd_mempool_destruct_t) g_hash_table_destroy,
					mime_part->raw_headers);
				if (hdrs != NULL) {
					process_raw_headers (task, mime_part->raw_headers,
							hdrs, strlen (hdrs));
					g_free (hdrs);
				}

				mime_part->type = type;
				mime_part->content = part_content;
				mime_part->parent = md->parent;
				mime_part->filename = g_mime_part_get_filename (GMIME_PART (
							part));
				mime_part->mime = part;

				debug_task ("found part with content-type: %s/%s",
					type->type,
					type->subtype);
				g_ptr_array_add (task->parts, mime_part);
				/* Skip empty parts */
				process_text_part (task,
					part_content,
					type,
					mime_part,
					md->parent,
					(part_content->len <= 0));
			}
			else {
				msg_warn ("write to stream failed: %d, %s", errno,
					strerror (errno));
			}
#ifndef GMIME24
			g_object_unref (wrapper);
#endif
		}
		else {
			msg_warn ("cannot get wrapper for mime part, type of part: %s/%s",
				type->type,
				type->subtype);
		}
	}
	else {
		g_assert_not_reached ();
	}
}

static void
destroy_message (void *pointer)
{
	GMimeMessage *msg = pointer;

	msg_debug ("freeing pointer %p", msg);
	g_object_unref (msg);
}

gboolean
rspamd_message_parse (struct rspamd_task *task)
{
	GMimeMessage *message;
	GMimeParser *parser;
	GMimeStream *stream;
	GByteArray *tmp;
	GList *first, *cur;
	GMimePart *part;
	GMimeDataWrapper *wrapper;
	GMimeObject *parent;
	const GMimeContentType *ct;
	struct mime_text_part *p1, *p2;
	struct mime_foreach_data md;
	struct received_header *recv;
	gchar *mid, *url_str;
	const gchar *url_end, *p, *end;
	struct rspamd_url *subject_url;
	gsize len;
	gint64 hdr_start, hdr_end;
	gint rc, state = 0, diff, *pdiff;
	guint tw, dw;

	tmp = rspamd_mempool_alloc (task->task_pool, sizeof (GByteArray));
	p = task->msg.start;
	len = task->msg.len;
	/* Skip any space characters to avoid some bad messages to be unparsed */
	while (g_ascii_isspace (*p) && len > 0) {
		p ++;
		len --;
	}

	tmp->data = (guint8 *)p;
	tmp->len = len;

	stream = g_mime_stream_mem_new_with_byte_array (tmp);
	/*
	 * This causes g_mime_stream not to free memory by itself as it is memory allocated by
	 * pool allocator
	 */
	g_mime_stream_mem_set_owner (GMIME_STREAM_MEM (stream), FALSE);

	if (task->flags & RSPAMD_TASK_FLAG_MIME) {

		debug_task ("construct mime parser from string length %d",
			(gint)task->msg.len);
		/* create a new parser object to parse the stream */
		parser = g_mime_parser_new_with_stream (stream);
		g_object_unref (stream);

		/* parse the message from the stream */
		message = g_mime_parser_construct_message (parser);

		if (message == NULL) {
			msg_warn ("cannot construct mime from stream");
			g_set_error (&task->err, rspamd_message_quark(), RSPAMD_FILTER_ERROR,\
				"cannot parse MIME in the message");
			/* TODO: backport to 0.9 */
			g_object_unref (parser);
			return FALSE;
		}

		task->message = message;
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) destroy_message, task->message);

		/* Save message id for future use */
		task->message_id = g_mime_message_get_message_id (task->message);
		if (task->message_id == NULL) {
			task->message_id = "undef";
		}

		memset (&md, 0, sizeof (md));
		md.task = task;
#ifdef GMIME24
		g_mime_message_foreach (message, mime_foreach_callback, &md);
#else
		/*
		 * This is rather strange, but gmime 2.2 do NOT pass top-level part to foreach callback
		 * so we need to set up parent part by hands
		 */
		md.parent = g_mime_message_get_mime_part (message);
		g_object_unref (md.parent);
		g_mime_message_foreach_part (message, mime_foreach_callback, &md);
#endif

		debug_task ("found %ud parts in message", task->parts->len);
		if (task->queue_id == NULL) {
			task->queue_id = "undef";
		}

		hdr_start = g_mime_parser_get_headers_begin (parser);
		hdr_end = g_mime_parser_get_headers_end (parser);
		if (hdr_start != -1 && hdr_end != -1) {
			g_assert (hdr_start <= hdr_end);
			g_assert (hdr_end <= (gint64)len);
			task->raw_headers_content.begin = (gchar *)(p + hdr_start);
			task->raw_headers_content.len = (guint64)(hdr_end - hdr_start);

			if (task->raw_headers_content.len > 0) {
				process_raw_headers (task, task->raw_headers,
						task->raw_headers_content.begin,
						task->raw_headers_content.len);
			}
		}

		rspamd_images_process (task);

		/* Parse received headers */
		first =
			rspamd_message_get_header (task, "Received", FALSE);
		cur = first;
		while (cur) {
			recv =
				rspamd_mempool_alloc0 (task->task_pool,
					sizeof (struct received_header));
			parse_recv_header (task->task_pool, cur->data, recv);
			g_ptr_array_add (task->received, recv);
			cur = g_list_next (cur);
		}

		/* Extract data from received header if we were not given IP */
		if (task->received->len > 0 && (task->flags & RSPAMD_TASK_FLAG_NO_IP)) {
			recv = g_ptr_array_index (task->received, 0);
			if (recv->real_ip) {
				if (!rspamd_parse_inet_address (&task->from_addr, recv->real_ip)) {
					msg_warn ("cannot get IP from received header: '%s'",
							recv->real_ip);
					task->from_addr = NULL;
				}
			}
			if (recv->real_hostname) {
				task->hostname = recv->real_hostname;
			}
		}

		/* free the parser (and the stream) */
		g_object_unref (parser);
	}
	else {
		/* We got only message, no mime headers or anything like this */
		/* Construct fake message for it */
		message = g_mime_message_new (TRUE);
		task->message = message;
		if (task->from_envelope) {
			g_mime_message_set_sender (task->message,
					rspamd_task_get_sender (task));
		}
		/* Construct part for it */
		part = g_mime_part_new_with_type ("text", "html");
#ifdef GMIME24
		wrapper = g_mime_data_wrapper_new_with_stream (stream,
				GMIME_CONTENT_ENCODING_8BIT);
#else
		wrapper = g_mime_data_wrapper_new_with_stream (stream,
				GMIME_PART_ENCODING_8BIT);
#endif
		g_mime_part_set_content_object (part, wrapper);
		g_mime_message_set_mime_part (task->message, GMIME_OBJECT (part));
		/* Register destructors */
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,	 wrapper);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,	 part);
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) destroy_message, task->message);

		memset (&md, 0, sizeof (md));
		md.task = task;
#ifdef GMIME24
		g_mime_message_foreach (task->message, mime_foreach_callback, &md);
#else
		g_mime_message_foreach_part (task->message, mime_foreach_callback,
			&md);
#endif
		/* Generate message ID */
		mid = g_mime_utils_generate_message_id ("localhost.localdomain");
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_free, mid);
		g_mime_message_set_message_id (task->message, mid);
		task->message_id = mid;
		task->queue_id = mid;

		/* Set headers for message */
		if (task->subject) {
			g_mime_message_set_subject (task->message, task->subject);
		}
	}

	/* Set mime recipients and sender for the task */
	task->rcpt_mime = g_mime_message_get_all_recipients (message);
	if (task->rcpt_mime) {
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) g_object_unref,
			task->rcpt_mime);
#else
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t) internet_address_list_destroy,
			task->rcpt_mime);
#endif
	}
	task->from_mime = internet_address_list_parse_string(
			g_mime_message_get_sender (message));
	if (task->from_mime) {
#ifdef GMIME24
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) g_object_unref,
				task->from_mime);
#else
		rspamd_mempool_add_destructor (task->task_pool,
				(rspamd_mempool_destruct_t) internet_address_list_destroy,
				task->from_mime);
#endif
	}

	/* Parse urls inside Subject header */
	cur = rspamd_message_get_header (task, "Subject", FALSE);
	if (cur) {
		p = cur->data;
		len = strlen (p);
		end = p + len;

		while (p < end) {
			/* Search to the end of url */
			if (rspamd_url_find (task->task_pool, p, end - p, NULL, &url_end,
				&url_str, FALSE, &state)) {
				if (url_str != NULL) {
					subject_url = rspamd_mempool_alloc0 (task->task_pool,
							sizeof (struct rspamd_url));
					rc = rspamd_url_parse (subject_url, url_str,
							strlen (url_str), task->task_pool);

					if ((rc == URI_ERRNO_OK) && subject_url->hostlen > 0) {
						if (subject_url->protocol != PROTOCOL_MAILTO) {
							if (!g_hash_table_lookup (task->urls, subject_url)) {
								g_hash_table_insert (task->urls,
										subject_url,
										subject_url);
							}
						}
					}
					else if (rc != URI_ERRNO_OK) {
						msg_info ("extract of url '%s' failed: %s",
								url_str,
								rspamd_url_strerror (rc));
					}
				}
			}
			else {
				break;
			}
			p = url_end + 1;
		}
	}

	/* Calculate distance for 2-parts messages */
	if (task->text_parts->len == 2) {
		p1 = g_ptr_array_index (task->text_parts, 0);
		p2 = g_ptr_array_index (task->text_parts, 1);

		/* First of all check parent object */
		if (p1->parent && p1->parent == p2->parent) {
			parent = p1->parent;
			ct = g_mime_object_get_content_type (parent);
			if (ct == NULL ||
					!g_mime_content_type_is_type ((GMimeContentType *)ct,
							"multipart", "alternative")) {
				debug_task (
						"two parts are not belong to multipart/alternative container, skip check");
			}
			else {
				if (!IS_PART_EMPTY (p1) && !IS_PART_EMPTY (p2) &&
						p1->normalized_words && p2->normalized_words) {

					tw = MAX (p1->normalized_words->len, p2->normalized_words->len);

					if (tw > 0) {
						dw = rspamd_words_levenshtein_distance (p1->normalized_words,
								p2->normalized_words);
						diff = tw > 0 ? (100.0 * (gdouble)(tw - dw) / (gdouble)tw) : 100;

						debug_task (
								"different words: %d, total words: %d, "
								"got likeliness between parts of %d%%",
								dw, tw,
								diff);

						pdiff = rspamd_mempool_alloc (task->task_pool, sizeof (gint));
						*pdiff = diff;
						rspamd_mempool_set_variable (task->task_pool,
								"parts_distance",
								pdiff,
								NULL);
					}
				}
			}
		}
		else {
			debug_task (
					"message contains two parts but they are in different multi-parts");
		}
	}
	else {
		debug_task (
				"message has too many text parts, so do not try to compare "
				"them with each other");
	}

	return TRUE;
}

GList *
rspamd_message_get_header (struct rspamd_task *task,
	const gchar *field,
	gboolean strong)
{
	GList *gret = NULL;
	struct raw_header *rh;

	rh = g_hash_table_lookup (task->raw_headers, field);

	if (rh == NULL) {
		return NULL;
	}

	while (rh) {
		if (strong) {
			if (strcmp (rh->name, field) == 0) {
				gret = g_list_prepend (gret, rh);
			}
		}
		else {
			gret = g_list_prepend (gret, rh);
		}
		rh = rh->next;
	}

	if (gret != NULL) {
		rspamd_mempool_add_destructor (task->task_pool,
			(rspamd_mempool_destruct_t)g_list_free, gret);
	}

	return gret;
}
