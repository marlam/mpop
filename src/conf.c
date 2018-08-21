/*
 * conf.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2014, 2015, 2016, 2018
 * Martin Lambers <marlam@marlam.de>
 * Martin Stenberg <martin@gnutiken.se> (passwordeval support)
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "gettext.h"
#define _(string) gettext(string)

#include "delivery.h"
#include "list.h"
#include "tools.h"
#include "xalloc.h"
#include "conf.h"

/* buffer size for configuration file lines */
#define LINEBUFSIZE 501


/*
 * account_new()
 *
 * see conf.h
 */

account_t *account_new(const char *conffile, const char *id)
{
    account_t *a;
    a = xmalloc(sizeof(account_t));
    a->id = id ? xstrdup(id) : NULL;
    a->conffile = conffile ? xstrdup(conffile) : NULL;
    a->mask = 0;
    a->host = NULL;
    a->port = 0;                /* this must be set later */
    a->timeout = 180;
    a->pipelining = 2;
    a->received_header = 1;
    a->delivery_method = -1;
    a->delivery_args = NULL;
    a->uidls_file = NULL;       /* this must be set later */
    a->only_new = 1;
    a->keep = 0;
    a->killsize = -1;
    a->skipsize = -1;
    a->filter = NULL;
    a->auth_mech = xstrdup("");
    a->username = NULL;
    a->password = NULL;
    a->passwordeval = NULL;
    a->ntlmdomain = NULL;
    a->tls = 0;
    a->tls_nostarttls = 0;
    a->tls_key_file = NULL;
    a->tls_cert_file = NULL;
    a->tls_trust_file = NULL;
    a->tls_crl_file = NULL;
    a->tls_sha256_fingerprint = NULL;
    a->tls_sha1_fingerprint = NULL;
    a->tls_md5_fingerprint = NULL;
    a->tls_nocertcheck = 0;
    a->tls_min_dh_prime_bits = -1;
    a->tls_priorities = NULL;
    a->proxy_host = NULL;
    a->proxy_port = 0;
    a->source_ip = NULL;
    return a;
}


/*
 * account_copy()
 *
 * see conf.h
 */

account_t *account_copy(account_t *acc)
{
    account_t *a = NULL;

    if (acc)
    {
        a = xmalloc(sizeof(account_t));
        a->id = acc->id ? xstrdup(acc->id) : NULL;
        a->conffile = acc->conffile ? xstrdup(acc->conffile) : NULL;
        a->mask = acc->mask;
        a->host = acc->host ? xstrdup(acc->host) : NULL;
        a->port = acc->port;
        a->timeout = acc->timeout;
        a->pipelining = acc->pipelining;
        a->received_header = acc->received_header;
        a->delivery_method = acc->delivery_method;
        a->delivery_args =
            acc->delivery_args ? xstrdup(acc->delivery_args) : NULL;
        a->uidls_file = acc->uidls_file ? xstrdup(acc->uidls_file) : NULL;
        a->only_new = acc->only_new;
        a->keep = acc->keep;
        a->killsize = acc->killsize;
        a->skipsize = acc->skipsize;
        a->filter = acc->filter ? xstrdup(acc->filter) : NULL;
        a->auth_mech = acc->auth_mech ? xstrdup(acc->auth_mech) : NULL;
        a->username = acc->username ? xstrdup(acc->username) : NULL;
        a->password = acc->password ? xstrdup(acc->password) : NULL;
        a->passwordeval = acc->passwordeval ? xstrdup(acc->passwordeval) : NULL;
        a->ntlmdomain = acc->ntlmdomain ? xstrdup(acc->ntlmdomain) : NULL;
        a->tls = acc->tls;
        a->tls_nostarttls = acc->tls_nostarttls;
        a->tls_key_file = acc->tls_key_file ? xstrdup(acc->tls_key_file) : NULL;
        a->tls_cert_file =
            acc->tls_cert_file ? xstrdup(acc->tls_cert_file) : NULL;
        a->tls_trust_file =
            acc->tls_trust_file ? xstrdup(acc->tls_trust_file) : NULL;
        a->tls_crl_file =
            acc->tls_crl_file ? xstrdup(acc->tls_crl_file) : NULL;
        if (acc->tls_sha256_fingerprint)
        {
            a->tls_sha256_fingerprint = xmalloc(32);
            memcpy(a->tls_sha256_fingerprint, acc->tls_sha256_fingerprint, 32);
        }
        else
        {
            a->tls_sha256_fingerprint = NULL;
        }
        if (acc->tls_sha1_fingerprint)
        {
            a->tls_sha1_fingerprint = xmalloc(20);
            memcpy(a->tls_sha1_fingerprint, acc->tls_sha1_fingerprint, 20);
        }
        else
        {
            a->tls_sha1_fingerprint = NULL;
        }
        if (acc->tls_md5_fingerprint)
        {
            a->tls_md5_fingerprint = xmalloc(16);
            memcpy(a->tls_md5_fingerprint, acc->tls_md5_fingerprint, 16);
        }
        else
        {
            a->tls_md5_fingerprint = NULL;
        }
        a->tls_nocertcheck = acc->tls_nocertcheck;
        a->tls_min_dh_prime_bits = acc->tls_min_dh_prime_bits;
        a->tls_priorities =
            acc->tls_priorities ? xstrdup(acc->tls_priorities) : NULL;
        a->proxy_host = acc->proxy_host ? xstrdup(acc->proxy_host) : NULL;
        a->proxy_port = acc->proxy_port;
        a->source_ip = acc->source_ip ? xstrdup(acc->source_ip) : NULL;
    }
    return a;
}


/*
 * account_free()
 *
 * see conf.h
 */

void account_free(void *a)
{
    account_t *p = a;
    if (p)
    {
        free(p->id);
        free(p->conffile);
        free(p->host);
        free(p->delivery_args);
        free(p->uidls_file);
        free(p->filter);
        free(p->auth_mech);
        free(p->username);
        free(p->password);
        free(p->passwordeval);
        free(p->ntlmdomain);
        free(p->tls_key_file);
        free(p->tls_cert_file);
        free(p->tls_trust_file);
        free(p->tls_crl_file);
        free(p->tls_sha256_fingerprint);
        free(p->tls_sha1_fingerprint);
        free(p->tls_md5_fingerprint);
        free(p->tls_priorities);
        free(p->proxy_host);
        free(p->source_ip);
        free(p);
    }
}


/*
 * find_account()
 *
 * see conf.h
 */

account_t *find_account(list_t *acc_list, const char *id)
{
    account_t *a = NULL;
    char *acc_id;

    while (!list_is_empty(acc_list))
    {
        acc_list = acc_list->next;
        acc_id = ((account_t *)(acc_list->data))->id;
        if (acc_id && strcmp(id, acc_id) == 0)
        {
            a = acc_list->data;
            break;
        }
    }

    return a;
}


/*
 * is_on(), is_off()
 *
 * see conf.h
 */

int is_on(char *s)
{
    return (strcmp(s, "on") == 0);
}

int is_off(char *s)
{
    return (strcmp(s, "off") == 0);
}


/*
 * get_non_neg_int()
 *
 * see conf.h
 */

int get_non_neg_int(const char *s)
{
    long x;
    char *p;

    errno = 0;
    x = strtol(s, &p, 0);
    if (p == s || x < 0 || (x == LONG_MAX && errno == ERANGE) || x > INT_MAX)
    {
        x = -1;
    }
    else if (*p != '\0')
    {
        /* trailing garbage */
        x = -1;
    }

    return x;
}


/*
 * get_size_arg()
 *
 * see conf.h
 */

long long get_size_arg(const char *s)
{
    long long x;
    char *p;

    errno = 0;
    x = strtoll(s, &p, 0);
    if (p == s || x < 0 || (x == LLONG_MAX && errno == ERANGE))
    {
        x = -1;
    }
    else if (strcmp(p, "k") == 0)
    {
        x = (x > (LLONG_MAX >> 10)) ? -1 : (x << 10);
    }
    else if (strcmp(p, "m") == 0)
    {
        x = (x > (LLONG_MAX >> 20)) ? -1 : (x << 20);
    }
    else if (*p != '\0')
    {
        /* trailing garbage */
        x = -1;
    }

    return x;
}


/*
 * get_fingerprint()
 *
 * see conf.h
 */

unsigned char *get_fingerprint(const char *s, size_t len)
{
    unsigned char *fingerprint = xmalloc(len);
    unsigned char hex[2];
    size_t i, j;
    char c;

    if (strlen(s) != 2 * len + (len - 1))
    {
        free(fingerprint);
        return NULL;
    }
    for (i = 0; i < len; i++)
    {
        for (j = 0; j < 2; j++)
        {
            c = toupper((unsigned char)s[3 * i + j]);
            if (c >= '0' && c <= '9')
            {
                hex[j] = c - '0';
            }
            else if (c >= 'A' && c <= 'F')
            {
                hex[j] = c - 'A' + 10;
            }
            else
            {
                free(fingerprint);
                return NULL;
            }
        }
        if (i < len - 1 && s[3 * i + 2] != ':' && s[3 * i + 2] != ' ')
        {
            free(fingerprint);
            return NULL;
        }
        fingerprint[i] = (hex[0] << 4) | hex[1];
    }
    return fingerprint;
}


/*
 * check_auth_arg()
 *
 * see conf.h
 */

int check_auth_arg(char *arg)
{
    size_t l, i;

    if (*arg == '\0')
    {
        return 0;
    }
    else if (strcmp(arg, "user") == 0
            || strcmp(arg, "apop") == 0
            || strcmp(arg, "plain") == 0
            || strcmp(arg, "cram-md5") == 0
            || strcmp(arg, "digest-md5") == 0
            || strcmp(arg, "scram-sha-1") == 0
            || strcmp(arg, "gssapi") == 0
            || strcmp(arg, "external") == 0
            || strcmp(arg, "login") == 0
            || strcmp(arg, "ntlm") == 0)
    {
        l = strlen(arg);
        for (i = 0; i < l; i++)
        {
            arg[i] = toupper((unsigned char)arg[i]);
        }
        return 0;
    }
    else
    {
        return 1;
    }
}


/*
 * override_account()
 *
 * see conf.h
 */

void override_account(account_t *acc1, account_t *acc2)
{
    if (acc2->mask & ACC_HOST)
    {
        free(acc1->host);
        acc1->host = acc2->host ? xstrdup(acc2->host) : NULL;
    }
    if (acc2->mask & ACC_PORT)
    {
        acc1->port = acc2->port;
    }
    if (acc2->mask & ACC_TIMEOUT)
    {
        acc1->timeout = acc2->timeout;
    }
    if (acc2->mask & ACC_PIPELINING)
    {
        acc1->pipelining = acc2->pipelining;
    }
    if (acc2->mask & ACC_RECEIVED_HEADER)
    {
        acc1->received_header = acc2->received_header;
    }
    if (acc2->mask & ACC_DELIVERY)
    {
        acc1->delivery_method = acc2->delivery_method;
        free(acc1->delivery_args);
        acc1->delivery_args =
            acc2->delivery_args ? xstrdup(acc2->delivery_args) : NULL;
    }
    if (acc2->mask & ACC_UIDLS_FILE)
    {
        free(acc1->uidls_file);
        acc1->uidls_file = acc2->uidls_file ? xstrdup(acc2->uidls_file) : NULL;
    }
    if (acc2->mask & ACC_ONLY_NEW)
    {
        acc1->only_new = acc2->only_new;
    }
    if (acc2->mask & ACC_KEEP)
    {
        acc1->keep = acc2->keep;
    }
    if (acc2->mask & ACC_KILLSIZE)
    {
        acc1->killsize = acc2->killsize;
    }
    if (acc2->mask & ACC_SKIPSIZE)
    {
        acc1->skipsize = acc2->skipsize;
    }
    if (acc2->mask & ACC_FILTER)
    {
        acc1->filter = acc2->filter ? xstrdup(acc2->filter) : NULL;
    }
    if (acc2->mask & ACC_AUTH_MECH)
    {
        free(acc1->auth_mech);
        acc1->auth_mech = acc2->auth_mech ? xstrdup(acc2->auth_mech) : NULL;
    }
    if (acc2->mask & ACC_USERNAME)
    {
        free(acc1->username);
        acc1->username = acc2->username ? xstrdup(acc2->username) : NULL;
    }
    if (acc2->mask & ACC_PASSWORD)
    {
        free(acc1->password);
        acc1->password = acc2->password ? xstrdup(acc2->password) : NULL;
    }
    if (acc2->mask & ACC_PASSWORDEVAL)
    {
        free(acc1->passwordeval);
        acc1->passwordeval =
            acc2->passwordeval ? xstrdup(acc2->passwordeval) : NULL;
    }
    if (acc2->mask & ACC_NTLMDOMAIN)
    {
        free(acc1->ntlmdomain);
        acc1->ntlmdomain = acc2->ntlmdomain ? xstrdup(acc2->ntlmdomain) : NULL;
    }
    if (acc2->mask & ACC_TLS)
    {
        acc1->tls = acc2->tls;
    }
    if (acc2->mask & ACC_TLS_NOSTARTTLS)
    {
        acc1->tls_nostarttls = acc2->tls_nostarttls;
    }
    if (acc2->mask & ACC_TLS_KEY_FILE)
    {
        free(acc1->tls_key_file);
        acc1->tls_key_file =
            acc2->tls_key_file ? xstrdup(acc2->tls_key_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_CERT_FILE)
    {
        free(acc1->tls_cert_file);
        acc1->tls_cert_file =
            acc2->tls_cert_file ? xstrdup(acc2->tls_cert_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_TRUST_FILE)
    {
        free(acc1->tls_trust_file);
        acc1->tls_trust_file =
            acc2->tls_trust_file ? xstrdup(acc2->tls_trust_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_CRL_FILE)
    {
        free(acc1->tls_crl_file);
        acc1->tls_crl_file =
            acc2->tls_crl_file ? xstrdup(acc2->tls_crl_file) : NULL;
    }
    if (acc2->mask & ACC_TLS_FINGERPRINT)
    {
        free(acc1->tls_sha256_fingerprint);
        if (acc2->tls_sha256_fingerprint)
        {
            acc1->tls_sha256_fingerprint = xmalloc(32);
            memcpy(acc1->tls_sha256_fingerprint, acc2->tls_sha256_fingerprint, 32);
        }
        else
        {
            acc1->tls_sha256_fingerprint = NULL;
        }
        free(acc1->tls_sha1_fingerprint);
        if (acc2->tls_sha1_fingerprint)
        {
            acc1->tls_sha1_fingerprint = xmalloc(20);
            memcpy(acc1->tls_sha1_fingerprint, acc2->tls_sha1_fingerprint, 20);
        }
        else
        {
            acc1->tls_sha1_fingerprint = NULL;
        }
        free(acc1->tls_md5_fingerprint);
        if (acc2->tls_md5_fingerprint)
        {
            acc1->tls_md5_fingerprint = xmalloc(16);
            memcpy(acc1->tls_md5_fingerprint, acc2->tls_md5_fingerprint, 16);
        }
        else
        {
            acc1->tls_md5_fingerprint = NULL;
        }
    }
    if (acc2->mask & ACC_TLS_NOCERTCHECK)
    {
        acc1->tls_nocertcheck = acc2->tls_nocertcheck;
    }
    if (acc2->mask & ACC_TLS_MIN_DH_PRIME_BITS)
    {
        acc1->tls_min_dh_prime_bits = acc2->tls_min_dh_prime_bits;
    }
    if (acc2->mask & ACC_TLS_PRIORITIES)
    {
        free(acc1->tls_priorities);
        acc1->tls_priorities = acc2->tls_priorities
            ? xstrdup(acc2->tls_priorities) : NULL;
    }
    if (acc2->mask & ACC_PROXY_HOST)
    {
        free(acc1->proxy_host);
        acc1->proxy_host = acc2->proxy_host ? xstrdup(acc2->proxy_host) : NULL;
    }
    if (acc2->mask & ACC_PROXY_PORT)
    {
        acc1->proxy_port = acc2->proxy_port;
    }
    if (acc2->mask & ACC_SOURCE_IP)
    {
        free(acc1->source_ip);
        acc1->source_ip = acc2->source_ip ? xstrdup(acc2->source_ip) : NULL;
    }
    acc1->mask |= acc2->mask;
}


/*
 * check_account()
 *
 * see conf.h
 */

int check_account(account_t *acc, int retrmail, char **errstr)
{
    if (!acc->host)
    {
        *errstr = xasprintf(_("host not set"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_key_file && !acc->tls_cert_file)
    {
        *errstr = xasprintf(_("tls_key_file requires tls_cert_file"));
        return CONF_ESYNTAX;
    }
    if (!acc->tls_key_file && acc->tls_cert_file)
    {
        *errstr = xasprintf(_("tls_cert_file requires tls_key_file"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_nocertcheck && acc->tls_trust_file)
    {
        *errstr = xasprintf(
                _("cannot use tls_trust_file with tls_certcheck turned off"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_nocertcheck
            && (acc->tls_sha256_fingerprint
                || acc->tls_sha1_fingerprint || acc->tls_md5_fingerprint))
    {
        *errstr = xasprintf(
                _("cannot use tls_fingerprint with tls_certcheck turned off"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_trust_file
            && (acc->tls_sha256_fingerprint
                || acc->tls_sha1_fingerprint || acc->tls_md5_fingerprint))
    {
        *errstr = xasprintf(
                _("cannot use both tls_trust_file and tls_fingerprint"));
        return CONF_ESYNTAX;
    }
    if (acc->tls && !acc->tls_trust_file
            && !acc->tls_sha256_fingerprint && !acc->tls_sha1_fingerprint
            && !acc->tls_md5_fingerprint && !acc->tls_nocertcheck)
    {
        *errstr = xasprintf(
                _("tls requires either tls_trust_file (highly recommended) "
                    "or tls_fingerprint or a disabled tls_certcheck"));
        return CONF_ESYNTAX;
    }
    if (acc->tls_crl_file && !acc->tls_trust_file)
    {
        *errstr = xasprintf(_("tls_crl_file requires tls_trust_file"));
        return CONF_ESYNTAX;
    }
    if (retrmail && acc->delivery_method == -1)
    {
        *errstr = xasprintf(_("no delivery information"));
        return CONF_ESYNTAX;
    }

    return CONF_EOK;
}


/*
 * get_password_eval()
 *
 * see conf.h
 */

int get_password_eval(const char *arg, char **buf, char **errstr)
{
    FILE *eval;
    size_t l;
    int have_more_data;

    *buf = NULL;
    *errstr = NULL;
    errno = 0;

    if (!(eval = popen(arg, "r")))
    {
        if (errno == 0)
        {
            errno = ENOMEM;
        }
        *errstr = xasprintf(_("cannot evaluate '%s': %s"), arg, strerror(errno));
        return CONF_EIO;
    }

    *buf = xmalloc(LINEBUFSIZE);
    if (!fgets(*buf, LINEBUFSIZE, eval))
    {
        *errstr = xasprintf(_("cannot read output of '%s'"), arg);
        pclose(eval);
        free(*buf);
        *buf = NULL;
        return CONF_EIO;
    }
    have_more_data = (fgetc(eval) != EOF);
    pclose(eval);

    l = strlen(*buf);
    if (l > 0)
    {
        if ((*buf)[l - 1] != '\n' && have_more_data)
        {
            *errstr = xasprintf(_("output of '%s' is longer than %d characters"),
                    arg, LINEBUFSIZE - 1);
            free(*buf);
            *buf = NULL;
            return CONF_EIO;
        }
        if ((*buf)[l - 1] == '\n')
        {
            (*buf)[l - 1] = '\0';
            if (l - 1 > 0 && (*buf)[l - 2] == '\r')
            {
                (*buf)[l - 2] = '\0';
            }
        }
    }

    return CONF_EOK;
}


/*
 * some small helper functions
 */

int is_blank(int c)
{
    return (c == ' ' || c == '\t');
}

int skip_blanks(const char *s, int i)
{
    while (is_blank(s[i]))
    {
        i++;
    }
    return i;
}

int get_cmd_length(const char *s)
{
    int i = 0;

    while (s[i] != '\0' && !is_blank(s[i]))
    {
        i++;
    }
    return i;
}

/* get index of last non-blank character. -1 means there is none. */
int get_last_nonblank(const char *s)
{
    int i;

    i = (int)strlen(s) - 1;
    while (i >= 0 && is_blank(s[i]))
    {
        i--;
    }
    return i;
}

/* Return string without whitespace at beginning and end. If the string is
 * enclosed in double quotes, remove these, too. String is allocated. */
char *trim_string(const char *s)
{
    char *t;
    int i;
    int l;

    i = skip_blanks(s, 0);
    l = get_last_nonblank(s + i);
    if (l >= 1 && s[i] == '"' && s[i + l] == '"')
    {
        t = xmalloc(l * sizeof(char));
        strncpy(t, s + i + 1, l - 1);
        t[l - 1] = '\0';
    }
    else
    {
        t = xmalloc((l + 2) * sizeof(char));
        strncpy(t, s + i, l + 1);
        t[l + 1] = '\0';
    }
    return t;
}


/*
 * get_next_cmd()
 *
 * Read a line from 'f'. Split it in a command part (first word after
 * whitespace) and an argument part (the word after the command).
 * Whitespace is ignored.
 * Sets the flag 'empty_line' if the line is empty.
 * Sets the flag 'eof' if EOF occurred.
 * On errors, 'empty_line' and 'eof', 'cmd' and 'arg' NULL.
 * On success, 'cmd' and 'arg' are allocated strings.
 * Used error codes: CONF_EIO, CONF_EPARSE
 */

int get_next_cmd(FILE *f, char **cmd, char **arg, int *empty_line, int *eof,
        char **errstr)
{
    char line[LINEBUFSIZE];
    char *p;
    int i;
    int l;

    *eof = 0;
    *empty_line = 0;
    *cmd = NULL;
    *arg = NULL;
    if (!fgets(line, (int)sizeof(line), f))
    {
        if (ferror(f))
        {
            *errstr = xasprintf(_("input error"));
            return CONF_EIO;
        }
        else /* EOF */
        {
            *eof = 1;
            return CONF_EOK;
        }
    }

    /* Kill '\n'. Beware: sometimes the last line of a file has no '\n' */
    if ((p = strchr(line, '\n')))
    {
        *p = '\0';
        /* Kill '\r' (if CRLF line endings are used) */
        if (p > line && *(p - 1) == '\r')
        {
            *(p - 1) = '\0';
        }
    }
    else if (strlen(line) == LINEBUFSIZE - 1)
    {
        *errstr = xasprintf(_("line longer than %d characters"),
                LINEBUFSIZE - 1);
        return CONF_EPARSE;
    }

    i = skip_blanks(line, 0);

    if (line[i] == '#' || line[i] == '\0')
    {
        *empty_line = 1;
        return CONF_EOK;
    }

    l = get_cmd_length(line + i);
    *cmd = xmalloc((l + 1) * sizeof(char));
    strncpy(*cmd, line + i, (size_t)l);
    (*cmd)[l] = '\0';

    *arg = trim_string(line + i + l);

    return CONF_EOK;
}


/*
 * read_account_list()
 *
 * Helper function for the account command: For every account name in the comma
 * separated string 's' search the account in 'acc_list' and add a pointer to
 * it to 'l'.
 */

int read_account_list(int line, list_t *acc_list, char *s, list_t *l,
        char **errstr)
{
    list_t *lp = l;
    char *comma;
    char *acc_id;
    account_t *acc;

    for (;;)
    {
        comma = strchr(s, ',');
        if (comma)
        {
            *comma = '\0';
        }
        acc_id = trim_string(s);
        if (*acc_id == '\0')
        {
            free(acc_id);
            *errstr = xasprintf(_("line %d: missing account name"), line);
            return CONF_ESYNTAX;
        }
        if (!(acc = find_account(acc_list, acc_id)))
        {
            *errstr = xasprintf(_("line %d: account %s not (yet) defined"),
                    line, acc_id);
            free(acc_id);
            return CONF_ESYNTAX;
        }
        free(acc_id);
        list_insert(lp, acc);
        lp = lp->next;
        if (comma)
        {
            s = comma + 1;
        }
        else
        {
            break;
        }
    }
    return CONF_EOK;
}


/*
 * read_conffile()
 *
 * Read configuration data from 'f' and store it in 'acc_list'.
 * The name of the configuration file, 'conffile', will be stored in the
 * "conffile" field of each account.
 * Unless an error code is returned, 'acc_list' will always be a new list;
 * it may be empty if no accounts were found.
 * If the file contains secrets (e.g. passwords), then the flag
 * 'conffile_contains_secrets' will be set to 1, else to 0.
 * Used error codes: CONF_EIO, CONF_EPARSE, CONF_ESYNTAX
 */

int read_conffile(const char *conffile, FILE *f, list_t **acc_list,
        int *conffile_contains_secrets, char **errstr)
{
    int e;
    list_t *p;
    account_t *defaults;
    account_t *acc;
    int line;
    char *cmd;
    char *arg;
    int empty_line;
    int eof;
    /* temporary variables: */
    char *acc_id;
    char *t;
    list_t *copy_from;
    list_t *lp;


    *conffile_contains_secrets = 0;
    defaults = account_new(NULL, NULL);
    *acc_list = list_new();
    p = *acc_list;
    acc = NULL;
    e = CONF_EOK;

    for (line = 1; ; line++)
    {
        if ((e = get_next_cmd(f, &cmd, &arg, &empty_line, &eof,
                        errstr)) != CONF_EOK)
        {
            break;
        }
        if (empty_line)
        {
            continue;
        }
        if (eof)
        {
            break;
        }

        if (!acc && strcmp(cmd, "account") != 0 && strcmp(cmd, "defaults") != 0)
        {
            *errstr = xasprintf(
                    _("line %d: first command must be account or defaults"),
                    line);
            e = CONF_ESYNTAX;
            break;
        }
        else if (strcmp(cmd, "defaults") == 0)
        {
            if (*arg != '\0')
            {
                *errstr = xasprintf(
                        _("line %d: command %s does not take an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            acc = defaults;
        }
        else if (strcmp(cmd, "account") == 0)
        {
            copy_from = list_new();
            if ((t = strchr(arg, ':')))
            {
                if ((e = read_account_list(line, *acc_list, t + 1, copy_from,
                                errstr)) != CONF_EOK)
                {
                    list_free(copy_from);
                    break;
                }
                *t = '\0';
                acc_id = trim_string(arg);
            }
            else
            {
                acc_id = xstrdup(arg);
            }
            if (*acc_id == '\0')
            {
                list_free(copy_from);
                *errstr = xasprintf(_("line %d: missing account name"), line);
                e = CONF_ESYNTAX;
                break;
            }
            if (strchr(acc_id, ':') || strchr(acc_id, ','))
            {
                list_free(copy_from);
                *errstr = xasprintf(_("line %d: an account name must not "
                            "contain colons or commas"), line);
                e = CONF_ESYNTAX;
                break;
            }
            if (find_account(*acc_list, acc_id))
            {
                list_free(copy_from);
                *errstr = xasprintf(
                        _("line %d: account %s was already defined"),
                        line, arg);
                e = CONF_ESYNTAX;
                break;
            }
            acc = account_copy(defaults);
            acc->id = acc_id;
            acc->conffile = xstrdup(conffile);
            acc->mask = 0;
            list_insert(p, acc);
            p = p->next;
            lp = copy_from;
            while (!list_is_empty(lp))
            {
                lp = lp->next;
                override_account(acc, lp->data);
            }
            list_free(copy_from);
        }
        else if (strcmp(cmd, "host") == 0)
        {
            acc->mask |= ACC_HOST;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                free(acc->host);
                acc->host = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "port") == 0)
        {
            acc->mask |= ACC_PORT;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                acc->port = get_non_neg_int(arg);
                if (acc->port < 1 || acc->port > 65535)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "timeout") == 0)
        {
            acc->mask |= ACC_TIMEOUT;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                if (is_off(arg))
                {
                    acc->timeout = 0;
                }
                else
                {
                    acc->timeout = get_non_neg_int(arg);
                    if (acc->timeout < 1)
                    {
                        *errstr = xasprintf(_("line %d: invalid argument %s "
                                    "for command %s"), line, arg, cmd);
                        e = CONF_ESYNTAX;
                        break;
                    }
                }
            }
        }
        else if (strcmp(cmd, "pipelining") == 0)
        {
            acc->mask |= ACC_PIPELINING;
            if (*arg == '\0' || is_on(arg))
            {
                acc->pipelining = 1;
            }
            else if (is_off(arg))
            {
                acc->pipelining = 0;
            }
            else if (strcmp(arg, "auto") == 0)
            {
                acc->pipelining = 2;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "received_header") == 0)
        {
            acc->mask |= ACC_RECEIVED_HEADER;
            if (*arg == '\0' || is_on(arg))
            {
                acc->received_header = 1;
            }
            else if (is_off(arg))
            {
                acc->received_header = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "delivery") == 0)
        {
            acc->mask |= ACC_DELIVERY;
            if (strncmp(arg, "mda", 3) == 0 && is_blank(arg[3]))
            {
                acc->delivery_method = DELIVERY_METHOD_MDA;
                free(acc->delivery_args);
                acc->delivery_args = trim_string(arg + 4);
            }
            else if (strncmp(arg, "maildir", 7) == 0 && is_blank(arg[7]))
            {
                acc->delivery_method = DELIVERY_METHOD_MAILDIR;
                free(acc->delivery_args);
                t = trim_string(arg + 8);
                acc->delivery_args = expand_tilde(t);
                free(t);
            }
            else if (strncmp(arg, "mbox", 4) == 0 && is_blank(arg[4]))
            {
                acc->delivery_method = DELIVERY_METHOD_MBOX;
                free(acc->delivery_args);
                t = trim_string(arg + 5);
                acc->delivery_args = expand_tilde(t);
                free(t);
            }
            else if (strncmp(arg, "exchange", 8) == 0 && is_blank(arg[8]))
            {
                acc->delivery_method = DELIVERY_METHOD_EXCHANGE;
                free(acc->delivery_args);
                t = trim_string(arg + 9);
                acc->delivery_args = expand_tilde(t);
                free(t);
            }
            else if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "uidls_file") == 0)
        {
            acc->mask |= ACC_UIDLS_FILE;
            free(acc->uidls_file);
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else
            {
                acc->uidls_file = expand_tilde(arg);
            }
        }
        else if (strcmp(cmd, "auth") == 0)
        {
            acc->mask |= ACC_AUTH_MECH;
            free(acc->auth_mech);
            if (*arg == '\0' || is_on(arg))
            {
                acc->auth_mech = xstrdup("");
            }
            else if (check_auth_arg(arg) == 0)
            {
                acc->auth_mech = xstrdup(arg);
            }
            else
            {
                acc->auth_mech = NULL;
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "user") == 0)
        {
            acc->mask |= ACC_USERNAME;
            free(acc->username);
            acc->username = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "password") == 0)
        {
            *conffile_contains_secrets = 1;
            acc->mask |= ACC_PASSWORD;
            free(acc->password);
            acc->password = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "passwordeval") == 0)
        {
            acc->mask |= ACC_PASSWORDEVAL;
            free(acc->passwordeval);
            acc->passwordeval = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "ntlmdomain") == 0)
        {
            acc->mask |= ACC_NTLMDOMAIN;
            free(acc->ntlmdomain);
            acc->ntlmdomain = (*arg == '\0') ? NULL : xstrdup(arg);
        }
        else if (strcmp(cmd, "tls") == 0)
        {
            acc->mask |= ACC_TLS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls = 1;
            }
            else if (is_off(arg))
            {
                acc->tls = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_starttls") == 0)
        {
            acc->mask |= ACC_TLS_NOSTARTTLS;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls_nostarttls = 0;
            }
            else if (is_off(arg))
            {
                acc->tls_nostarttls = 1;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_key_file") == 0)
        {
            acc->mask |= ACC_TLS_KEY_FILE;
            free(acc->tls_key_file);
            acc->tls_key_file = (*arg == '\0') ? NULL : expand_tilde(arg);
        }
        else if (strcmp(cmd, "tls_cert_file") == 0)
        {
            acc->mask |= ACC_TLS_CERT_FILE;
            free(acc->tls_cert_file);
            acc->tls_cert_file = (*arg == '\0') ? NULL : expand_tilde(arg);
        }
        else if (strcmp(cmd, "tls_trust_file") == 0)
        {
            acc->mask |= ACC_TLS_TRUST_FILE;
            free(acc->tls_trust_file);
            acc->tls_trust_file = (*arg == '\0') ? NULL : expand_tilde(arg);
        }
        else if (strcmp(cmd, "tls_crl_file") == 0)
        {
            acc->mask |= ACC_TLS_CRL_FILE;
            free(acc->tls_crl_file);
            acc->tls_crl_file = (*arg == '\0') ? NULL : expand_tilde(arg);
        }
        else if (strcmp(cmd, "tls_fingerprint") == 0)
        {
            acc->mask |= ACC_TLS_FINGERPRINT;
            free(acc->tls_sha256_fingerprint);
            acc->tls_sha256_fingerprint = NULL;
            free(acc->tls_sha1_fingerprint);
            acc->tls_sha1_fingerprint = NULL;
            free(acc->tls_md5_fingerprint);
            acc->tls_md5_fingerprint = NULL;
            if (*arg != '\0')
            {
                if (strlen(arg) == 2 * 32 + 31)
                {
                    acc->tls_sha256_fingerprint = get_fingerprint(arg, 32);
                }
                else if (strlen(arg) == 2 * 20 + 19)
                {
                    acc->tls_sha1_fingerprint = get_fingerprint(arg, 20);
                }
                else if (strlen(arg) == 2 * 16 + 15)
                {
                    acc->tls_md5_fingerprint = get_fingerprint(arg, 16);
                }
                if (!acc->tls_sha256_fingerprint && !acc->tls_sha1_fingerprint
                        && !acc->tls_md5_fingerprint)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "tls_certcheck") == 0)
        {
            acc->mask |= ACC_TLS_NOCERTCHECK;
            if (*arg == '\0' || is_on(arg))
            {
                acc->tls_nocertcheck = 0;
            }
            else if (is_off(arg))
            {
                acc->tls_nocertcheck = 1;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "tls_min_dh_prime_bits") == 0)
        {
            acc->mask |= ACC_TLS_MIN_DH_PRIME_BITS;
            if (*arg == '\0')
            {
                acc->tls_min_dh_prime_bits = -1;
            }
            else
            {
                acc->tls_min_dh_prime_bits = get_non_neg_int(arg);
                if (acc->tls_min_dh_prime_bits < 1)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "tls_priorities") == 0)
        {
            acc->mask |= ACC_TLS_PRIORITIES;
            free(acc->tls_priorities);
            if (*arg == '\0')
            {
                acc->tls_priorities = NULL;
            }
            else
            {
                acc->tls_priorities = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "only_new") == 0)
        {
            acc->mask |= ACC_ONLY_NEW;
            if (*arg == '\0' || is_on(arg))
            {
                acc->only_new = 1;
            }
            else if (is_off(arg))
            {
                acc->only_new = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "keep") == 0)
        {
            acc->mask |= ACC_KEEP;
            if (*arg == '\0' || is_on(arg))
            {
                acc->keep = 1;
            }
            else if (is_off(arg))
            {
                acc->keep = 0;
            }
            else
            {
                *errstr = xasprintf(
                        _("line %d: invalid argument %s for command %s"),
                        line, arg, cmd);
                e = CONF_ESYNTAX;
                break;
            }
        }
        else if (strcmp(cmd, "killsize") == 0)
        {
            acc->mask |= ACC_KILLSIZE;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else if (is_off(arg))
            {
                acc->killsize = -1;
            }
            else
            {
                if ((acc->killsize = get_size_arg(arg)) < 0)
                {
                    *errstr = xasprintf(_("line %d: invalid size (not a number "
                                "or out of range): %s"), line, arg);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "skipsize") == 0)
        {
            acc->mask |= ACC_SKIPSIZE;
            if (*arg == '\0')
            {
                *errstr = xasprintf(_("line %d: command %s needs an argument"),
                        line, cmd);
                e = CONF_ESYNTAX;
                break;
            }
            else if (is_off(arg))
            {
                acc->skipsize = -1;
            }
            else
            {
                if ((acc->skipsize = get_size_arg(arg)) < 0)
                {
                    *errstr = xasprintf(_("line %d: invalid size (not a number "
                                "or out of range): %s"), line, arg);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "filter") == 0)
        {
            acc->mask |= ACC_FILTER;
            free(acc->filter);
            if (*arg == '\0')
            {
                acc->filter = NULL;
            }
            else
            {
                acc->filter = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "proxy_host") == 0)
        {
            acc->mask |= ACC_PROXY_HOST;
            free(acc->proxy_host);
            if (*arg == '\0')
            {
                acc->proxy_host = NULL;
            }
            else
            {
                acc->proxy_host = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "proxy_port") == 0)
        {
            acc->mask |= ACC_PROXY_PORT;
            if (*arg == '\0')
            {
                acc->proxy_port = 0;
            }
            else
            {
                acc->proxy_port = get_non_neg_int(arg);
                if (acc->proxy_port < 1 || acc->proxy_port > 65535)
                {
                    *errstr = xasprintf(
                            _("line %d: invalid argument %s for command %s"),
                            line, arg, cmd);
                    e = CONF_ESYNTAX;
                    break;
                }
            }
        }
        else if (strcmp(cmd, "source_ip") == 0)
        {
            acc->mask |= ACC_SOURCE_IP;
            free(acc->source_ip);
            if (*arg == '\0')
            {
                acc->source_ip = NULL;
            }
            else
            {
                acc->source_ip = xstrdup(arg);
            }
        }
        else if (strcmp(cmd, "tls_force_sslv3") == 0)
        {
            /* compatibility with versions <= 1.0.29: silently ignore */
        }
        else
        {
            *errstr = xasprintf(_("line %d: unknown command %s"), line, cmd);
            e = CONF_ESYNTAX;
            break;
        }
        free(cmd);
        free(arg);
    }
    free(cmd);
    free(arg);

    if (e != CONF_EOK)
    {
        list_xfree(*acc_list, account_free);
        *acc_list = NULL;
    }
    account_free(defaults);

    return e;
}


/*
 * get_conf()
 *
 * see conf.h
 */

int get_conf(const char *conffile, int securitycheck, list_t **acc_list,
        char **errstr)
{
    FILE *f;
    int conffile_contains_secrets;
    int e;

    if (!(f = fopen(conffile, "r")))
    {
        *errstr = xasprintf("%s", strerror(errno));
        return CONF_EIO;
    }
    if ((e = read_conffile(conffile, f, acc_list, &conffile_contains_secrets,
                    errstr)) != CONF_EOK)
    {
        fclose(f);
        return e;
    }
    fclose(f);
    e = CONF_EOK;
    if (securitycheck && conffile_contains_secrets)
    {
        switch (check_secure(conffile))
        {
            case 1:
                *errstr = xasprintf(_("contains secrets and therefore "
                            "must be owned by you"));
                e = CONF_EINSECURE;
                break;

            case 2:
                *errstr = xasprintf(_("contains secrets and therefore "
                            "must have no more than user "
                            "read/write permissions"));
                e = CONF_EINSECURE;
                break;

            case 3:
                *errstr = xasprintf("%s", strerror(errno));
                e = CONF_EIO;
                break;
        }
    }

    return e;
}
