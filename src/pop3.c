/*
 * pop3.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2003, 2004, 2005, 2006, 2007
 * Martin Lambers <marlam@marlam.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software Foundation,
 *   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#if HAVE_SIGACTION
# include <signal.h>
#endif

#ifdef HAVE_LIBIDN
# include <idna.h>
#endif

#ifdef HAVE_LIBGSASL
# include <gsasl.h>
#else
# include "base64.h"
# include "hmac.h"
#endif

#include "c-ctype.h"
#include "gettext.h"
#include "md5.h"
#include "xalloc.h"
#include "xvasprintf.h"

#include "delivery.h"
#include "net.h"
#include "tools.h"
#include "stream.h"
#ifdef HAVE_TLS
# include "tls.h"
#endif /* HAVE_TLS */
#include "pop3.h"


/*
 * This defines the maximum amount of mails that a POP3 account is allowed to
 * have. This limit prevents size_t overflows when allocating memory. Example:
 * 	session->msg_size = xmalloc(session->total_number * sizeof(long));
 * This is the only reason for this limit; you can raise it depending on 
 * the values of sizeof(long) and sizeof(char *) of your platform.
 */
#define POP3_MAX_MESSAGES	1000000


/*
 * This defines the maximum number of lines that the reply to the CAPA command 
 * is allowed to have. This prevents endless replies.
 */
#define POP3_MAX_CAPAREPLY_LINES	50


/*
 * The following numbers are used for POP3 pipelining:
 * Pipelining works by sending up to PIPELINE_MAX commands to the server, then 
 * begin to read its answers, and refill the command pipeline when the number of
 * unanswered commands drops to PIPELINE_MIN.
 */
#ifndef POP3_PIPELINE_MIN
#define POP3_PIPELINE_MIN	20
#endif
#ifndef POP3_PIPELINE_MAX
#define POP3_PIPELINE_MAX	100
#endif


/*
 * pop3_session_new()
 *
 * see pop3.h
 */

pop3_session_t *pop3_session_new(int pipelining,
	const char *local_hostname, const char *local_user,
	FILE *debug)
{
    pop3_session_t *session;
    char *p;

    session = xmalloc(sizeof(pop3_session_t));
    session->local_hostname = xstrdup(local_hostname);
    session->local_user = xstrdup(local_user);
    /* sanitize the user name because it will appear in Received headers */
    for (p = session->local_user; *p; p++)
    {
	if (c_isspace((unsigned char)*p))
	{
	    *p = '-';
	}
	else if (!c_isalpha((unsigned char)*p) && !c_isdigit((unsigned char)*p)
    		&& *p != '-' && *p != '_' && *p != '.')
	{
	    *p = '_';
	}
    }
    session->fd = -1;
    session->server_hostname = NULL;
    session->server_canonical_name = NULL;
    session->server_address = NULL;
    net_readbuf_init(&(session->readbuf));
#ifdef HAVE_TLS
    tls_clear(&session->tls);
#endif /* HAVE_TLS */
    session->cap.flags = 0;
    session->pipelining = pipelining;
    /* every POP3 server supports this: */
    session->cap.flags |= POP3_CAP_AUTH_USER;
    session->cap.apop_timestamp = NULL;
    session->cap.implementation = NULL;
    session->count_newline_as_crlf = 0;
    session->debug = debug;
    session->total_number = 0;
    session->total_size = 0;
    session->is_old = NULL;
    session->old_number = 0;
    session->new_number = 0;
    session->new_size = 0;
    session->msg_size = NULL;
    session->msg_uid = NULL;
    session->uids_sorted = NULL;
    session->msg_action = NULL;

    return session;
}


/*
 * pop3_session_free()
 *
 * see pop3.h
 */

void pop3_session_free(pop3_session_t *session)
{
    long i;
    
    free(session->local_hostname);
    free(session->local_user);
    free(session->server_hostname);
    free(session->server_canonical_name);
    free(session->server_address);
    free(session->cap.apop_timestamp);
    free(session->cap.implementation);
    if (session->msg_uid)
    {
	for (i = 0; i < session->total_number; i++)
	{
	    free(session->msg_uid[i]);
	}
	free(session->msg_uid);
    }
    free(session->uids_sorted);
    free(session->msg_action);
    free(session->is_old);
    free(session->msg_size);
    free(session);
}


/*
 * pop3_connect()
 *
 * see pop3.h
 */

int pop3_connect(pop3_session_t *session, 
	const char *server_hostname, int port, int timeout,
	const char **server_canonical_name, const char **server_address, 
	char **errstr)
{
    int e;
    
    session->server_hostname = xstrdup(server_hostname);
    e = net_open_socket(server_hostname, port, timeout, &session->fd, 
	    &session->server_canonical_name, &session->server_address, errstr);
    if (server_canonical_name)
    {
	*server_canonical_name = session->server_canonical_name;
    }
    if (server_address)
    {
	*server_address = session->server_address;
    }
    return e;
}


/*
 * pop3_gets()
 *
 * Reads in at most one less than POP3_BUFSIZE characters from the POP3 server
 * and stores them into the buffer. Reading stops after an EOF or a newline.
 * If a newline is read, it is stored into the buffer. A '\0' is stored after 
 * the last character in the buffer. The length of the resulting string (the
 * number of characters excluding the terminating '\0') will be stored in 'len'.
 * If an error occured, '\0' is stored in buffer[0], and 'len' will be 0.
 * Used error codes: POP3_EIO
 */

int pop3_gets(pop3_session_t *session, size_t *len, char **errstr)
{
    int e = 0;
    
#ifdef HAVE_TLS
    if (tls_is_active(&session->tls))
    {
	e = (tls_gets(&session->tls, session->buffer, POP3_BUFSIZE, len, errstr)
		!= TLS_EOK);
    }
    else
    {
#endif /* HAVE_TLS */
	e = (net_gets(session->fd, &(session->readbuf), 
		    session->buffer, POP3_BUFSIZE, len, errstr) != NET_EOK);
#ifdef HAVE_TLS
    }
#endif /* HAVE_TLS */
    if (e)
    {
	*len = 0;
	return POP3_EIO;
    }
    if (session->debug)
    {
	fputs("<-- ", session->debug);
  	fwrite(session->buffer, sizeof(char), *len, session->debug);
    }
    return POP3_EOK;
}


/*
 * pop3_get_msg()
 *
 * This function gets a POP3 server message (one line).
 * The line will at least contain "+OK" or "-ERR", unless 'sasl' is set, in
 * which case it will at least contain "+ " or "- ".
 * In case of errors, the buffer will contain an empty string.
 * Used error codes: POP3_EIO, POP3_EPROTO
 */

int pop3_get_msg(pop3_session_t *session, int sasl, char **errstr)
{
    int e;
    size_t l;
    int valid = 1;

    if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (l < 3 || session->buffer[l - 1] != '\n')
    {
	valid = 0;
    }
    if (sasl)
    {
	if (strncmp(session->buffer, "+ ", 2) != 0 
		&& strncmp(session->buffer, "- ", 2) != 0
		&& strncmp(session->buffer, "+OK", 3) != 0 
		&& strncmp(session->buffer, "-ERR", 4) != 0)
	{
	    valid = 0;
	}
    }
    else
    {
	if (strncmp(session->buffer, "+OK", 3) != 0 
		&& strncmp(session->buffer, "-ERR", 4) != 0)
	{
	    valid = 0;
	}
    }
    if (!valid)	    
    {
	/* The string is not necessarily a reply (it may be the initial OK
    	 * message), but this is the term used in the RFCs.
	 * An empty reply is a special case of an invalid reply - this
	 * differentiation may help the user. */
	if (l == 0)
	{
	    *errstr = xasprintf(_("POP3 server sent an empty reply"));
	}
	else
	{
	    *errstr = xasprintf(_("POP3 server sent an invalid reply"));
	}
	return POP3_EPROTO;
    }
    /* kill CRLF. The string is at least 3 chars long and ends with '\n'. */
    session->buffer[l - 1] = '\0';
    if (session->buffer[l - 2] == '\r')
    {
	session->buffer[l - 2] = '\0';
    }

    return POP3_EOK;
}


/*
 * pop3_msg_ok()
 *
 * Returns whether the POP3 status of the POP3 server message 's' is OK.
 */

int pop3_msg_ok(const char *s)
{
    return (s[0] == '+');
}


/*
 * pop3_send_cmd()
 *
 * This function writes a string to the POP3 server. TCP CRLF ('\r\n') will be
 * appended to the string.
 * Used error codes: POP3_EIO, POP3_EINVAL
 */

/* make gcc print format warnings for this function */
#ifdef __GNUC__
int pop3_send_cmd(pop3_session_t *session, char **errstr, 
	const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));
#endif

int pop3_send_cmd(pop3_session_t *session, char **errstr, 
	const char *format, ...)
{
    int e;
    char line[POP3_BUFSIZE];
    int count;
    va_list args;

    va_start(args, format);
    count = vsnprintf(line, POP3_BUFSIZE - 2, format, args);
    va_end(args);
    if (count >= POP3_BUFSIZE - 2)
    {
	*errstr = xasprintf(_("Cannot send POP3 command because it is "
    		    "longer than %d characters. Increase POP3_BUFSIZE."), 
		POP3_BUFSIZE - 3);
	return POP3_EINVAL;
    }
    line[count++] = '\r';
    line[count++] = '\n';
    line[count] = '\0';
#ifdef HAVE_TLS
    if (tls_is_active(&session->tls))
    {
	e = (tls_puts(&session->tls, line, (size_t)count, errstr) != TLS_EOK);
    }
    else
    {
#endif /* HAVE_TLS */
	e = (net_puts(session->fd, line, (size_t)count, errstr) != NET_EOK);
#ifdef HAVE_TLS
    }
#endif /* HAVE_TLS */
    if (e)
    {
	return POP3_EIO;
    }
    if (session->debug)
    {
	fputs("--> ", session->debug);
 	fwrite(line, sizeof(char), (size_t)count, session->debug);
    }
    
    return POP3_EOK;
}


/*
 * pop3_get_addr()
 *
 * Reads the next mail address from the given string and returns it in an
 * allocated buffer. If no mail address is found, NULL will be returned.
 * If a buffer is returned, the string in it will only contain the following
 * characters: letters a-z and A-Z, digits 0-9, and any of ".@_-+/".
 * Note that this is only a subset of what the RFCs 2821 and 2822 allow!
 */
char *pop3_get_addr(const char *s)
{
    enum states { STATE_DEFAULT, STATE_DQUOTE, 
	STATE_BRACKETS_START, STATE_IN_BRACKETS, 
	STATE_PARENTH_START, STATE_IN_PARENTH,
	STATE_IN_ADDRESS, STATE_BACKQUOTE,
        STATE_END };
    int state = STATE_DEFAULT;
    int oldstate = STATE_DEFAULT;
    int backquote_savestate = STATE_DEFAULT;
    int parentheses_depth = 0;
    int parentheses_savestate = STATE_DEFAULT;
    char *addr = NULL;
    size_t addr_len = 0;
    int forget_addr = 0;
    int finish_addr = 0;
    size_t bufsize = 0;
    /* The buffer that is filled with the mail address grows by
     * 'bufsize_step' if the remaining space becomes too small. This value must
     * be at least 2. Wasted characters are at most (bufsize_step - 1). A value
     * of 10 means low wasted space and a low number of realloc()s per
     * recipient. */
    const size_t bufsize_step = 10;
    const char *p = s;
 
    for (;;)
    {
	oldstate = state;
	if (!*p)
	{
	    if (addr)
		finish_addr = 1;
	    state = STATE_END;
	}
	else
	{
	    switch (state)
	    {
	       	case STATE_DEFAULT:
	    	    if (*p == '\\')
	    	    {
	       		backquote_savestate = state;
	    		state = STATE_BACKQUOTE;
	    	    }
	    	    else if (*p == '(')
	    	    {
	    		parentheses_savestate = state;
	    		state = STATE_PARENTH_START;
	    	    }
	    	    else if (*p == '"')
	    	    {
	    		if (addr)
	    		    forget_addr = 1;
	    		state = STATE_DQUOTE;
	    	    }
	    	    else if (*p == '<')
	    	    {
	    		if (addr)
	    		    forget_addr = 1;
	    		state = STATE_BRACKETS_START;
	    	    }
	    	    else if (*p == ' ' || *p == '\t')
	    		; /* keep state */
	    	    else if (*p == ':')
	    	    {
	    		if (addr)
	    		    forget_addr = 1;
	    	    }
	    	    else if (*p == ';' || *p == ',')
	    	    {
	    		if (addr)
			{
	    		    finish_addr = 1;
			    state = STATE_END;
			}
	    	    }
	    	    else
	    	    {
	    		if (addr)
	    		    forget_addr = 1;
	    		state = STATE_IN_ADDRESS;
	    	    }
	    	    break;

		case STATE_DQUOTE:
	    	    if (*p == '\\')
	    	    {
	    		backquote_savestate = state;
	    		state = STATE_BACKQUOTE;
	    	    }
	    	    else if (*p == '"')
	    		state = STATE_DEFAULT;
	    	    break;

		case STATE_BRACKETS_START:
	    	    if (*p == '(')
	    	    {
	    		parentheses_savestate = state;
	    		state = STATE_PARENTH_START;
	    	    }
	    	    else if (*p == '>')
	    		state = STATE_DEFAULT;
	    	    else
	    		state = STATE_IN_BRACKETS;
	    	    break;

		case STATE_IN_BRACKETS:
	    	    if (*p == '\\')
	    	    {
	    		backquote_savestate = state;
	    		state = STATE_BACKQUOTE;
	    	    }
	    	    else if (*p == '(')
	    	    {
	    		parentheses_savestate = state;
	    		state = STATE_PARENTH_START;
	    	    }
	    	    else if (*p == '>')
		    {
			finish_addr = 1;
	    		state = STATE_END;
    		    }
	    	    break;

		case STATE_PARENTH_START:
	    	    if (*p == ')')
	    		state = parentheses_savestate;
	    	    else
	    	    {
	    		parentheses_depth++;
	    		state = STATE_IN_PARENTH;
	    	    }
	    	    break;

		case STATE_IN_PARENTH:
	    	    if (*p == '\\')
	    	    {
	    		backquote_savestate = state;
	    		state = STATE_BACKQUOTE;
	    	    }
	    	    else if (*p == '(')
	    		state = STATE_PARENTH_START;
	    	    else if (*p == ')')
	    	    {
	    		parentheses_depth--;
	    		if (parentheses_depth == 0)
	    		    state = parentheses_savestate;
	    	    }
	    	    break;

		case STATE_IN_ADDRESS:
	    	    if (*p == '\\')
	    	    {
	    		backquote_savestate = state;
	    		state = STATE_BACKQUOTE;
	    	    }
	    	    else if (*p == '"')
	    	    {
	    		forget_addr = 1;
	    		state = STATE_DQUOTE;
	    	    }
	    	    else if (*p == '(')
	    	    {
	    		parentheses_savestate = state;
	    		state = STATE_PARENTH_START;
	    	    }
	    	    else if (*p == '<')
	    	    {
	    		forget_addr = 1;
	    		state = STATE_BRACKETS_START;
	    	    }
	    	    else if (*p == ' ' || *p == '\t')
	    		state = STATE_DEFAULT;
	    	    else if (*p == ':')
	    	    {
	    		forget_addr = 1;
	    		state = STATE_DEFAULT;
	    	    }
	    	    else if (*p == ',' || *p == ';')
		    {
	    		finish_addr = 1;
	    		state = STATE_END;
    		    }
	    	    break;

		case STATE_BACKQUOTE:
		    state = backquote_savestate;
		    break;
	    }
	}

	if (forget_addr)
	{
	    /* this was just junk */
	    free(addr);
	    addr = NULL;
	    addr_len = 0;
	    bufsize = 0;
	    forget_addr = 0;
	}
	if (finish_addr)
	{
	    addr[addr_len] = '\0';
	}
	if (state == STATE_END)
	{
	    break;
	}
	if ((state == STATE_IN_ADDRESS || state == STATE_IN_BRACKETS)
		&& oldstate != STATE_PARENTH_START
		&& oldstate != STATE_IN_PARENTH)
	{
    	    /* Add this character to the current recipient */
	    addr_len++;
	    if (bufsize < addr_len + 1)
	    {
		bufsize += bufsize_step;
		addr = xrealloc(addr, bufsize * sizeof(char));
	    }
	    /* sanitize characters */
	    if (c_isalpha((unsigned char)*p) || c_isdigit((unsigned char)*p)
		    || *p == '.' || *p == '@' || *p == '_' || *p == '-' 
		    || *p == '+' || *p == '/')
	    {
		addr[addr_len - 1] = *p;
	    }
	    else if (c_isspace((unsigned char)*p))
	    {
		addr[addr_len - 1] = '-';
	    }
	    else
	    {
		addr[addr_len - 1] = '_';
	    }
	}
	p++;
    }

    return addr;
}


/*
 * pop3_get_greeting()
 *
 * see pop3.h
 */

int pop3_get_greeting(pop3_session_t *session, char *greeting, 
	char **errmsg, char **errstr)
{
    int e;
    char *p, *q, *a;
    
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(
		_("cannot get initial OK message from POP3 server"));
	return POP3_EPROTO;
    }
    if (greeting)
    {
	/* 'greeting' is large enough */
	strcpy(greeting, session->buffer + 4);
    }
    /* Search APOP timestamp. Make sure that it is a valid RFC822 message id as
     * required by RFC 1939 and that it is reasonably long. This should make
     * man-in-the-middle attacks as described in CVE-2007-1558 a little bit
     * harder. Nevertheless, APOP is considered broken, and is never used
     * automatically unless TLS is active. */
    a = NULL;
    if ((p = strchr(session->buffer, '<')) != NULL	/* start of timestamp */
	    && (q = strchr(p + 1, '>')) != NULL		/* end of timestamp */
	    && (q - p + 1) >= 12			/* minimum length */
	    && (a = pop3_get_addr(p))			/* valid address */
	    && strlen(a) + 2 == (size_t)(q - p + 1)	/* no specials */
	    && strncmp(p + 1, a, q - p - 1) == 0)	/* no invalid chars */
    {
	session->cap.flags |= POP3_CAP_AUTH_APOP;
	session->cap.apop_timestamp = xmalloc((q - p + 2) * sizeof(char));
	strncpy(session->cap.apop_timestamp, p, q - p + 1);
	session->cap.apop_timestamp[q - p + 1] = '\0';
    }
    free(a);

    return POP3_EOK;
}


/*
 * pop3_capa()
 *
 * see pop3.h
 */

int pop3_capa(pop3_session_t *session, char **errstr)
{
    int e;
    int count;
    size_t l;
    size_t i;
    
    /* Set the CAPA capability. Reset it if the server does not support the CAPA
     * command. */
    session->cap.flags |= POP3_CAP_CAPA;

    if ((e = pop3_send_cmd(session, errstr, "CAPA")) != POP3_EOK)
    {
	return e;
    }
    for (count = 0; count < POP3_MAX_CAPAREPLY_LINES; count++)
    {
	if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (l < 1 || session->buffer[l - 1] != '\n')
	{
	    *errstr = xasprintf(_("invalid reply to command %s"), "CAPA");
	    return POP3_EPROTO;
	}
	if (count == 0 && session->buffer[0] == '-')
	{
	    /* The server does not support the CAPA command */
	    session->cap.flags ^= POP3_CAP_CAPA;
	    break;
	}
	else if (session->buffer[0] == '.' 
		&& (session->buffer[1] == '\r' || session->buffer[1] == '\n'))
	{
	    break;
	}
	else 
	{
	    i = 0;
	    /* We know that the line ends with "\n" */
	    while (!isspace((unsigned char)session->buffer[i]))
	    {
		session->buffer[i] = toupper((unsigned char)session->buffer[i]);
		i++;
	    }
	    if (strncmp(session->buffer, "TOP", 3) == 0)
	    {
		session->cap.flags |= POP3_CAP_TOP;
	    }
	    else if (strncmp(session->buffer, "LOGIN-DELAY", 11) == 0)
	    {
		session->cap.flags |= POP3_CAP_LOGIN_DELAY;
		session->cap.login_delay = atol(session->buffer + 11);
		if (session->cap.login_delay < 0)
		{
		    session->cap.login_delay = 0;
		}
	    }
	    else if (strncmp(session->buffer, "PIPELINING", 10) == 0)
	    {
		session->cap.flags |= POP3_CAP_PIPELINING;
	    }
	    else if (strncmp(session->buffer, "EXPIRE", 6) == 0)
	    {
		session->cap.flags |= POP3_CAP_EXPIRE;
		while (session->buffer[i])
		{
		    session->buffer[i] = 
			toupper((unsigned char)session->buffer[i]);
		    i++;
		}
		if (strstr(session->buffer + 6, "NEVER"))
		{
		    session->cap.expire = LONG_MAX;
		}
		else
		{
		    session->cap.expire = atol(session->buffer + 6);
		    if (session->cap.expire < 0)
		    {
			session->cap.expire = 0;
		    }
		}
	    }
	    else if (strncmp(session->buffer, "UIDL", 4) == 0)
	    {
		session->cap.flags |= POP3_CAP_UIDL;
	    }
	    else if (strncmp(session->buffer, "STLS", 4) == 0)
	    {
		session->cap.flags |= POP3_CAP_STLS;
	    }	
	    else if (strncmp(session->buffer, "USER", 4) == 0)
	    {
		session->cap.flags |= POP3_CAP_AUTH_USER;
	    }
	    else if (strncmp(session->buffer, "SASL ", 5) == 0)
	    {
		while (session->buffer[i])
		{
		    session->buffer[i] = 
			toupper((unsigned char)session->buffer[i]);
		    i++;
		}
		if (strstr(session->buffer + 5, "PLAIN"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_PLAIN;
		}
		if (strstr(session->buffer + 5, "CRAM-MD5"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_CRAM_MD5;
		}
		if (strstr(session->buffer + 5, "DIGEST-MD5"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_DIGEST_MD5;
		}
		if (strstr(session->buffer + 5, "GSSAPI"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_GSSAPI;
		}
		if (strstr(session->buffer + 5, "EXTERNAL"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_EXTERNAL;
		}
		if (strstr(session->buffer + 5, "LOGIN"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_LOGIN;
		}
		if (strstr(session->buffer + 5, "NTLM"))
		{
		    session->cap.flags |= POP3_CAP_AUTH_NTLM;
		}
	    }
	    else if (strncmp(session->buffer, "IMPLEMENTATION", 14) == 0)
	    {
		session->cap.flags |= POP3_CAP_IMPLEMENTATION;
		for (i = 14; session->buffer[i] == ' '; i++);
		l = strlen(session->buffer + i);
		if (session->buffer[i + l - 1] == '\n')
		{
		    session->buffer[i + l - 1] = '\0';
		    if (session->buffer[i + l - 2] == '\r')
		    {
			session->buffer[i + l - 2] = '\0';
		    }
		}
		free(session->cap.implementation);
		session->cap.implementation = xstrdup(session->buffer + i);
	    }
	    else if (strncmp(session->buffer, "RESP-CODES", 10) == 0)
	    {
		session->cap.flags |= POP3_CAP_RESP_CODES;
	    }
	    else if (strncmp(session->buffer, "AUTH-RESP-CODE", 14) == 0)
	    {
		session->cap.flags |= POP3_CAP_AUTH_RESP_CODE;
	    }
	}
    }
    if (count == POP3_MAX_CAPAREPLY_LINES)
    {
	*errstr = xasprintf(_("invalid reply to command %s"), "CAPA");
	return POP3_EPROTO;
    }
    
    /* Automatically set the pipelining flag to off (0) or on (1) if it is not
     * already set. */
    if (session->pipelining == 2)
    {
	if (session->cap.flags & POP3_CAP_CAPA 
		&& session->cap.flags & POP3_CAP_PIPELINING)
	{
	    session->pipelining = 1;
	}
	else
	{
	    session->pipelining = 0;
	}
    }
    
    return POP3_EOK;
}


/*
 * pop3_tls_init()
 *
 * see pop3.h
 */

#ifdef HAVE_TLS
int pop3_tls_init(pop3_session_t *session, const char *tls_key_file, 
	const char *tls_ca_file, const char *tls_trust_file, 
	int force_sslv3, char **errstr)
{
    return tls_init(&session->tls, tls_key_file, tls_ca_file, tls_trust_file, 
	    force_sslv3, errstr);
}
#endif /* HAVE_TLS */


/*
 * pop3_tls_stls()
 *
 * see pop3.h
 */

#ifdef HAVE_TLS
int pop3_tls_stls(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;

    if ((e = pop3_send_cmd(session, errstr, "STLS")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "STLS");
	return POP3_EPROTO;
    }
    return POP3_EOK;
}
#endif /* HAVE_TLS */


/*
 * pop3_tls()
 *
 * see pop3.h
 */

#ifdef HAVE_TLS
int pop3_tls(pop3_session_t *session, const char *hostname, int tls_nocertcheck,
	tls_cert_info_t *tci, char **errstr)
{
    return tls_start(&session->tls, session->fd, hostname, tls_nocertcheck, tci,
	    errstr);
}
#endif /* HAVE_TLS */


/*
 * pop3_stat()
 *
 * see pop3.h
 */

int pop3_stat(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;
    char *p, *q;
    long i;

    if ((e = pop3_send_cmd(session, errstr, "STAT")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "STAT");
	return POP3_EPROTO;
    }
    errno = 0;
    session->total_number = strtol(session->buffer + 4, &p, 10);
    if ((p == session->buffer + 4) || *p != ' ' || session->total_number < 0 
	    || (session->total_number == LONG_MAX && errno == ERANGE))
    {
	*errstr = xasprintf(_("invalid reply to command %s"), "STAT");
	return POP3_EPROTO;
    }
    errno = 0;
    session->total_size = strtol(p + 1, &q, 10);
    if ((q == p + 1) || session->total_size < 0 
	    || (session->total_size == LONG_MAX && errno == ERANGE))
    {
	*errstr = xasprintf(_("invalid reply to command %s"), "STAT");
	return POP3_EPROTO;
    }
    /* Protect against size_t overflows in the xmalloc() calls that depend on
     * the total number of messages, below and in other functions */
    if (session->total_number > POP3_MAX_MESSAGES)
    {
	*errstr = xasprintf(_("Cannot handle more than %lu messages. "
		    "Increase POP3_MAX_MESSAGES."), 
		(unsigned long) POP3_MAX_MESSAGES);
	return POP3_ELIBFAILED;
    }
    /* Requesting potentially very large amounts of memory here! */
    session->msg_action = (session->total_number == 0) ? NULL :
	xmalloc(session->total_number * sizeof(unsigned char));
    session->is_old = (session->total_number == 0) ? NULL :
	xmalloc(session->total_number * sizeof(unsigned char));
    for (i = 0; i < session->total_number; i++)
    {
	session->msg_action[i] = POP3_MSG_ACTION_NORMAL;
	session->is_old[i] = 0;
    }    
    session->new_number = session->total_number;
    session->new_size = session->total_size;

    return POP3_EOK;
}


/*
 * pop3_uidl()
 *
 * see pop3.h
 */

/* Helper: insert the index of an uid such that the array of indices gives the
 * UIDs in sorted (ascending) order */
void insert_sorted(long *strings_sorted, long len, char **strings, 
	long new_index)
{
    long a = 0;
    long b = len - 1;
    long c;

    while (b >= a)
    {
	c = (a + b) / 2;
	if (strcmp(strings[strings_sorted[c]], strings[new_index]) <= 0)
	{
	    a = c + 1;
	}
	else
	{
	    b = c - 1;
	}
    }
    for (c = len; c > a; c--)
    {
	strings_sorted[c] = strings_sorted[c - 1];
    }
    strings_sorted[a] = new_index;
}

/* Helper: Check if a UID is valid. */
int pop3_uidl_check_uid(const char *uid)
{
    const char *p = uid;
    
    /* According to RFC 1939, a valid UID must consist of one to 70 characters
     * in the range 0x21 to 0x7e. We allow longer UIDs, spaces inside UIDs, and
     * non-ASCII characters in UIDs as long as they are not control characters.
     * I know of one case where the POP3 server uses non-ASCII characters in 
     * UIDs. I don't know if any server needs the other extensions, though. */
    while (*p != '\0')
    {
	if (c_iscntrl((unsigned char)*p))
	{
	    return 0;
	}
	p++;
    }
    return (p != uid);
}

int pop3_uidl(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;
    long i;
    char *p;
    size_t l;
    long n;

    if ((e = pop3_send_cmd(session, errstr, "UIDL")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "UIDL");
	return POP3_EUNAVAIL;
    }

    /* initialize the UIDs so that we can later check if all of them were set */
    session->msg_uid = (session->total_number == 0) ? NULL :
	xmalloc(session->total_number * sizeof(char *));
    for (i = 0; i < session->total_number; i++)
    {
	session->msg_uid[i] = NULL;
    }
    session->uids_sorted = (session->total_number == 0) ? NULL :
	xmalloc(session->total_number * sizeof(long));

    /* get 'total_number' UIDs plus one stop line (".") */
    for (i = 0; i < session->total_number + 1; i++)
    {
	if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
	{
	    goto error_exit;
	}
	if (l < 2 || session->buffer[l - 1] != '\n')
	{
	    goto invalid_reply;
	}
	session->buffer[--l] = '\0';
	if (session->buffer[l - 1] == '\r')
	{
	    session->buffer[--l] = '\0';
	}
	if (session->buffer[0] == '.' && l == 1)
	{
	    break;
	}
	else if (i >= session->total_number)
	{
	    goto invalid_reply;
	}
	else
	{
	    errno = 0;
	    n = strtol(session->buffer, &p, 10);
	    if (p == session->buffer || *p != ' ' 
		    || (n == LONG_MAX && errno == ERANGE)
		    || n < 1 || n > session->total_number
		    || session->msg_uid[n - 1])
	    {
		goto invalid_reply;
	    }
	    /* Allow more than one space between the number and the UID, even
	     * though RFC 1939 says it must be exactly one. Needed for the
	     * "Maillennium V05.00c++" POP3 server used by Comcast.net as of
	     * 2007-01-29. */
	    while (*p == ' ')
	    {
		p++;
	    }
	    if (!pop3_uidl_check_uid(p))
	    {
		goto invalid_reply;
	    }
	    session->msg_uid[n - 1] = xstrdup(p + 1);
	    insert_sorted(session->uids_sorted, i, session->msg_uid, n - 1);
	}
    }
    
    /* we have an UID for each message when we have 'total_number' UIDs, because
     * we know that none was double */
    if (i != session->total_number)
    {
	goto invalid_reply;
    }

    return POP3_EOK;
    
invalid_reply:
    *errstr = xasprintf(_("invalid reply to command %s"), "UIDL");
    e = POP3_EPROTO;

error_exit:
    for (i = 0; i < session->total_number; i++)
    {
	free(session->msg_uid[i]);
    }
    free(session->msg_uid);
    session->msg_uid = NULL;
    return e;
}


/*
 * pop3_list()
 *
 * see pop3.h
 */

int pop3_list(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;
    long i;
    char *p, *q;
    size_t l;
    long n;

    
    if ((e = pop3_send_cmd(session, errstr, "LIST")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "LIST");
	return POP3_EPROTO;
    }
    
    /* initialize the size so that we can later check if all of them were set */
    session->msg_size = (session->total_number == 0) ? NULL : 
	xmalloc(session->total_number * sizeof(long));
    for (i = 0; i < session->total_number; i++)
    {
	session->msg_size[i] = -1;
    }

    /* get 'total_number' sizes plus one stop line (".") */
    for (i = 0; i < session->total_number + 1; i++)
    {
	if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (l < 2 || session->buffer[l - 1] != '\n')
	{
	    goto invalid_reply;
	}
	session->buffer[--l] = '\0';
	if (session->buffer[l - 1] == '\r')
	{
	    session->buffer[--l] = '\0';
	}
	if (session->buffer[0] == '.' && l == 1)
	{
	    break;
	}
	else if (i == session->total_number)
	{
	    goto invalid_reply;
	}
	else
	{
	    errno = 0;
	    n = strtol(session->buffer, &p, 10);
	    if (p == session->buffer || *p != ' ' 
		    || (n == LONG_MAX && errno == ERANGE)
		    || n < 1 || n > session->total_number
		    || session->msg_size[n - 1] != -1)
	    {
		goto invalid_reply;
	    }
	    errno = 0;
	    session->msg_size[n - 1] = strtol(p + 1, &q, 10);
	    if (session->msg_size[n - 1] < 0 || q == p
		    || (session->msg_size[n - 1] == LONG_MAX 
			&& errno == ERANGE))
	    {
		goto invalid_reply;
	    }
	}
    }
    
    /* we have a size for each message when we have 'counter' sizes, because we
     * know that none was double */
    if (i != session->total_number)
    {
	goto invalid_reply;
    }

    return POP3_EOK;

invalid_reply:
    *errstr = xasprintf(_("invalid reply to command %s"), "LIST");
    return POP3_EPROTO;
}


/*
 * pop3_pipe()
 *
 * Pipe the message with the number 'i' (or a part thereof) to 'f'.
 * 'i' is the POP3 msg number, starting with 1, not 0!
 * If 'full_mail' is set, it is expected that the whole message is piped (this
 * is important for the internal setting count_newline_as_crlf that can only be
 * updated when the full mail is retrieved).
 * The progress output functions may be NULL.
 * If 'abort' is externally set, this function will immediately return
 * POP3_EABORT. The POP3 session is unusable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO
 */

int pop3_pipe(pop3_session_t *session, 
#if HAVE_SIGACTION
	volatile sig_atomic_t *abort,
#endif
	FILE *tmpf, FILE *f, long i, 
	int full_mail, int from_quoting,	
	void (*progress_start)(long i, long number, long size),
	void (*progress)(long i, long number, long rcvd, long size,
	    int percent),
	void (*progress_end)(long i, long number, long size),
	void (*progress_abort)(long i, long number, long size),
	char **errstr)
{
    int e;
    int read_from_tmpf;
    int line_starts;
    int line_continues;
    size_t l;
    char *p;
    long rcvd;
    int percent;
    int old_percent;
    
    if (progress_start)
    {
	progress_start(i, session->total_number, session->msg_size[i - 1]);
    }
    read_from_tmpf = tmpf ? 1 : 0;
    rcvd = 0;
    percent = 0;
    line_continues = 0;
    for (;;)
    {
#if HAVE_SIGACTION
	if (*abort)
	{
	    if (progress_abort)
	    {
    		progress_abort(i, session->total_number, 
			session->msg_size[i - 1]);
	    }
	    *errstr = xasprintf(_("operation aborted"));
	    return POP3_EABORT;
	}
#endif
	line_starts = !line_continues;
	if (read_from_tmpf)
	{
	    if (stream_gets(tmpf, session->buffer, POP3_BUFSIZE, &l, errstr)
		    != STREAM_EOK)
	    {
		if (progress_abort)
	    	{
    		    progress_abort(i, session->total_number, 
			    session->msg_size[i - 1]);
		}
		return POP3_EIO;
	    }
	    if (l == 0)
	    {
		/* we reached EOF */
	    	read_from_tmpf = 0;
    	    }
	}
	/* Don't use else here because read_from_tmpf might have been set to
	 * false in the block above. */
	if (!read_from_tmpf)
	{
	    if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
	    {
		if (progress_abort)
		{
		    progress_abort(i, session->total_number, 
		    	    session->msg_size[i - 1]);
		}
		return e;
	    }
	}
	if (l > 0 && session->buffer[l - 1] == '\n')
	{
	    /* first case: we have a line end */
	    session->buffer[--l] = '\0';
	    if (l > 0 && session->buffer[l - 1] == '\r')
	    {
		session->buffer[--l] = '\0';
	    }
	    line_continues = 0;	    
	}
	else if (l == POP3_BUFSIZE - 1)
	{
	    /* second case: the line continues */
	    if (session->buffer[l - 1] == '\r')
	    {
   		/* We have CRLF that is divided by the buffer boundary. Since CR
   		 * may not appear alone in a mail according to RFC2822, we
  		 * know that the next buffer will be "\n\0", so it's safe to
  		 * just delete the CR. */
		session->buffer[--l] = '\0';
	    }
     	    line_continues = 1;
	}
	else
	{
	    /* third case: this is the last line, and it lacks a newline
 	     * character */
   	    line_continues = 0;
	}
	p = session->buffer;
	if (line_starts)
	{
	    if (session->buffer[0] == '.')
	    {
		if (session->buffer[1] == '\0')
		{
		    /* end of mail */
		    break;
		}
		else
		{
		    /* remove leading dot */
		    p = session->buffer + 1;
		    l--;
		}
	    }
	}
	e = 0;
	if (line_starts && from_quoting)
	{
	    /* This is MBOXRD style From quoting. See
	     * http://www.qmail.org/qmail-manual-html/man5/mbox.html */
	    if (strncmp(session->buffer + strspn(session->buffer, ">"), 
			"From ", 5) == 0)
	    {
		e = (fputc('>', f) == EOF);
	    }
	}
	if (!e)
	{
	    e = (fwrite(p, sizeof(char), l, f) != l);
	}
	if (!e  && !line_continues)
	{
	    e = (fputc('\n', f) == EOF);
	}
	if (e)
	{
	    if (progress_abort)
	    {
		progress_abort(i, session->total_number, 
			session->msg_size[i - 1]);
	    }
	    *errstr = xasprintf(_("cannot write mail: output error"));
	    return POP3_EIO;
	}
	rcvd += (long)l - (p == session->buffer ? 0 : 1);
	if (!line_continues)
	{
	    rcvd += session->count_newline_as_crlf ? 2 : 1;
	}
	if (progress)
	{
	    old_percent = percent;
	    percent = (int)((float)rcvd 
		    / (float)session->msg_size[i - 1] * 100.0f);
	    if (percent > 99)
	    {
		percent = 99;
	    }
	    if (percent >= old_percent + 1)
	    {
		progress(i, session->total_number, 
			rcvd, session->msg_size[i - 1], percent);
	    }
	}
    }
    if (progress_end)
    {
	progress_end(i, session->total_number, session->msg_size[i - 1]);
    }
    if (full_mail && !session->count_newline_as_crlf 
	    && rcvd < session->msg_size[i])
    {
	session->count_newline_as_crlf = 1;
    }

    return POP3_EOK;
}


/* 
 * pop3_retr_get_from_addr()
 *
 * Copy the mail headers from the server into 'f', and find out the envelope
 * from address from the headers. Stop after writing the blank line that
 * separates header and body into 'f'. 'from_addr' will always be an allocated
 * buffer with a valid mail address or "MAILER-DAEMON" as a fallback. If an
 * envelope from address is found, it will only contain the following
 * characters: letters a-z and A-Z, digits 0-9, and any of ".@_-+/".
 * Note that this is only a subset of what the RFCs 2821 and 2822 allow!
 * Used error codes: POP3_EIO
 */

int pop3_retr_get_from_addr(pop3_session_t *session, FILE *f, char **from_addr,
	char **errstr)
{
    int e;
    int line_starts;
    int line_continues;
    size_t l;
    
    *from_addr = NULL;
    line_continues = 0;
    for (;;)
    {
	line_starts = !line_continues;
	if ((e = pop3_gets(session, &l, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (l > 0 && session->buffer[l - 1] == '\n')
	{
	    /* first case: we have a line end */
	    session->buffer[--l] = '\0';
	    if (l > 0 && session->buffer[l - 1] == '\r')
	    {
		session->buffer[--l] = '\0';
	    }
	    line_continues = 0;	    
	}
	else if (l == POP3_BUFSIZE - 1)
	{
	    /* second case: the line continues */
	    if (session->buffer[l - 1] == '\r')
	    {
   		/* We have CRLF that is divided by the buffer boundary. Since CR
   		 * may not appear alone in a mail according to RFC2822, we
  		 * know that the next buffer will be "\n\0", so it's safe to
  		 * just delete the CR. */
		session->buffer[--l] = '\0';
	    }
     	    line_continues = 1;
	}
	else
	{
	    /* third case: this is the last line, and it lacks a newline
 	     * character */
   	    line_continues = 0;
	}
	e = (fwrite(session->buffer, sizeof(char), l, f) != l);
	if (!e  && !line_continues)
	{
	    e = (fputc('\n', f) == EOF);
	}
	if (e)
	{
	    *errstr = xasprintf(
		    _("cannot write to temporary file: output error"));
	    return POP3_EIO;
	}
	if (line_starts)
	{
	    if (l == 0)
	    {
		/* this is the blank line separating the header from the body */
		break;
	    }
	    else if (!*from_addr)
	    {
		if (strncasecmp(session->buffer, "Return-Path:", 12) == 0)
		{
		    *from_addr = pop3_get_addr(session->buffer + 12);
		}
		else if (strncasecmp(session->buffer, "Sender:", 7) == 0)
		{
		    *from_addr = pop3_get_addr(session->buffer + 7);
		}
	    }
	}
    }
    /* Fallback */
    if (!*from_addr)
    {
	*from_addr = xstrdup("MAILER-DAEMON");
    }

    return POP3_EOK;
}


/*
 * pop3_write_received_header()
 *
 * Write a Received header to the given stream.
 */

int pop3_write_received_header(pop3_session_t *session, FILE *f, char **errstr)
{
    time_t t;
    struct tm gmt, *lt;
    char tz_offset_sign;
    int tz_offset_hours;
    int tz_offset_minutes;
    const char *weekday[7] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", 
	"Sat" };
    const char *month[12] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
	"Aug", "Sep", "Oct", "Nov", "Dec" };
    char rfc2822_timestamp[32];
#ifdef HAVE_LIBIDN
    char *hostname_ascii;
#endif
    int e;
    
    /* Calculate a RFC 2822 timestamp. strftime() is unreliable for this because
     * it is locale dependant, and because the timezone offset conversion
     * specifier %z is not portable. */
    if ((t = time(NULL)) < 0)
    {
	*errstr = xasprintf(_("cannot get system time: %s"), strerror(errno));
	return POP3_ELIBFAILED;
    }
    /* copy the struct tm, because the subsequent call to localtime() will
     * overwrite it */
    gmt = *gmtime(&t);
    lt = localtime(&t);
    tz_offset_minutes = (lt->tm_hour - gmt.tm_hour) * 60 
	+ lt->tm_min - gmt.tm_min
	+ (lt->tm_year - gmt.tm_year) * 24 * 60
	+ (lt->tm_yday - gmt.tm_yday) * 24 * 60;
    if (tz_offset_minutes < 0)
    {
	tz_offset_sign = '-';
	tz_offset_minutes = -tz_offset_minutes;
    }
    else
    {
	tz_offset_sign = '+';
    }
    tz_offset_hours = tz_offset_minutes / 60;
    tz_offset_minutes %= 60;
    if (tz_offset_hours > 99)
    {
	/* Values equal to or larger than 24 are not meaningful, but we just
	 * make sure that the value fits into two digits. If the system time is
	 * broken, we cannot fix it. */
	tz_offset_hours = 99;
    }
    (void)snprintf(rfc2822_timestamp, sizeof(rfc2822_timestamp),
	    "%s, %02d %s %04d %02d:%02d:%02d %c%02d%02d",
	    weekday[lt->tm_wday], lt->tm_mday, month[lt->tm_mon], 
	    lt->tm_year + 1900, lt->tm_hour, lt->tm_min, lt->tm_sec, 
	    tz_offset_sign, tz_offset_hours, tz_offset_minutes);
	    
    /* Write the Received header */
#ifdef HAVE_LIBIDN
    if (idna_to_ascii_lz(session->server_hostname, &hostname_ascii, 0) 
	    != IDNA_SUCCESS)
    {
	/* This should never happen, because we are already connected. */
	hostname_ascii = xstrdup(session->server_hostname);
    }
    e = (fprintf(f, "Received: from %s", hostname_ascii) < 0);
    free(hostname_ascii);
#else
    e = (fprintf(f, "Received: from %s", session->server_hostname) < 0);
#endif
    if (!e)
    {
	if (session->server_canonical_name && session->server_address)
	{
	    e = (fprintf(f, " (%s [%s])", session->server_canonical_name, 
			session->server_address) < 0);
	}
	else if (session->server_canonical_name)
	{
	    e = (fprintf(f, " (%s)", session->server_canonical_name) < 0);
	}
	else if (session->server_address)
	{
	    e = (fprintf(f, " ([%s])", session->server_address) < 0);
	}
    }
    if (!e)
    {
	e = (fprintf(f, "\n\tby %s (%s-%s) with POP3\n\tfor <%s>; %s\n",
		    session->local_hostname, PACKAGE_NAME, PACKAGE_VERSION,
		    session->local_user, rfc2822_timestamp) < 0);
    }
    if (e)
    {
	*errstr = xasprintf(_("cannot add Received header: %s"), 
		strerror(errno));
	return POP3_EIO;
    }

    return POP3_EOK;
}


/*
 * pop3_delivery()
 *
 * This function gets mails (via RETR) or mail headers (via TOP) and delivers
 * them with the functions defined in delivery.[ch].
 * When 'filter' is set, it handles filtering and uses TOP,
 * else it delivers mails (prepending a Received header) and uses RETR. 
 * See pop3_filter() and pop3_retr().
 * When 'abort' is externally set, this function will stop processing the
 * pipelined commands and return with POP3_EABORTED. The POP3 session is
 * unsuable thereafter.
 */

int pop3_delivery(pop3_session_t *session,
#if HAVE_SIGACTION
	volatile sig_atomic_t *abort,
#endif
	int filter, 
	void (*filter_output)(long i, long number, int new_status, 
	    void *filter_output_data),
	void *filter_output_data,
	int delivery_method, const char *delivery_method_arguments,
	void (*progress_start)(long i, long number, long size),
	void (*progress)(long i, long number, long rcvd, long size,
	    int percent),
	void (*progress_end)(long i, long number, long size),
	void (*progress_abort)(long i, long number, long size),
	char **errmsg, char **errstr)
{
    int e;
    int pipeline_min;
    int pipeline_max;
    long send_index;
    long recv_index;
    int piped_commands;
    delivery_method_t *delivery;
    FILE *tmpf;
    char *from_addr;
    char *errstr_bak;
    int filter_exit_code;

    
    if (session->pipelining)
    {
	pipeline_min = POP3_PIPELINE_MIN;
	pipeline_max = POP3_PIPELINE_MAX;
    }
    else
    {
	pipeline_min = 0;
	pipeline_max = 1;
    }
    tmpf = NULL;
    from_addr = NULL;	
    if (!(delivery = delivery_method_new(delivery_method, 
		    (void *)delivery_method_arguments, errstr)))
    {
	e = POP3_EDELIVERY;
	goto error_exit;
    }
    send_index = 0;
    recv_index = 0;
    piped_commands = 0;
    do
    {
	/* RECEIVE */
	for (; recv_index < session->total_number
		&& piped_commands > (send_index < session->total_number 
		    ? pipeline_min : 0);
		recv_index++)
	{
#if HAVE_SIGACTION
	    if (*abort)
	    {
		e = POP3_EABORT;
		*errstr = xasprintf(_("operation aborted"));
		goto error_exit;
	    }
#endif
	    if (session->msg_action[recv_index] != POP3_MSG_ACTION_NORMAL)
	    {
		continue;
	    }
	    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	    {
		goto error_exit;
	    }
	    if (!pop3_msg_ok(session->buffer))
	    {
		*errmsg = xstrdup(session->buffer);
		if (filter)
		{
		    *errstr = xasprintf(_("command TOP %ld 0 failed"), 
			    recv_index + 1);
		}
		else
		{
		    *errstr = xasprintf(_("command RETR %ld failed"), 
			    recv_index + 1);
		}
		e = POP3_EPROTO;
		goto error_exit;
	    }
	    /* get the from address if needed */
	    if (delivery->want_from_addr)
	    {
		if (!(tmpf = tempfile(PACKAGE_NAME)))
		{
		    *errstr = xasprintf(_("cannot create temporary file: %s"),
			    strerror(errno));
		    e = POP3_EDELIVERY;
		    goto error_exit;
		}
		if ((e = pop3_retr_get_from_addr(session, tmpf, &from_addr,
				errstr)) != POP3_EOK)
		{
		    goto error_exit;
		}
		if (fseek(tmpf, 0L, SEEK_SET) != 0)
	    	{
		    *errstr = xasprintf(_("cannot rewind temporary file: %s"), 
			    strerror(errno));
		    e = POP3_EDELIVERY;
	     	    goto error_exit;
	   	}
	    }
	    /* open pipe */
	    if (delivery->open(delivery, from_addr, 
			session->msg_size[recv_index], errstr) != DELIVERY_EOK)
	    {
		e = POP3_EDELIVERY;
		goto error_exit;
	    }
	    if (from_addr)
	    {
		free(from_addr);
		from_addr = NULL;
	    }
	    /* write a Received header */
	    if (!filter)
	    {
		if ((e = pop3_write_received_header(session, delivery->pipe, 
				errstr)) != POP3_EOK)
		{
		    goto error_exit;
		}
	    }
	    /* pipe the message (headers) */
	    if ((e = pop3_pipe(session, 
#if HAVE_SIGACTION
			    abort, 
#endif
			    tmpf, delivery->pipe, 
			    recv_index + 1, !filter, 
			    delivery->need_from_quoting,
		    	    progress_start, progress, progress_end, 
			    progress_abort, errstr)) != POP3_EOK)
	    {
		goto error_exit;
	    }
	    if (tmpf)
	    {
		(void)fclose(tmpf);
		tmpf = NULL;
	    }
	    if (filter)
	    {
		/* close filter; check exit code and update message status */
		filter_exit_code = delivery->close(delivery, errstr);
		if (filter_exit_code == 0)
		{
		    /* proceed normally */
		}
		else if (filter_exit_code == 1)
		{
		    /* kill mail */
		    session->msg_action[recv_index] = POP3_MSG_ACTION_DELETE;
		    if (filter_output)
		    {
			filter_output(recv_index + 1, session->total_number, 
			     	POP3_MSG_ACTION_DELETE, filter_output_data);
		    }
		}
		else if (filter_exit_code == 2)
		{
		    /* ignore mail */
		    session->msg_action[recv_index] = POP3_MSG_ACTION_IGNORE;
		    if (filter_output)
		    {
			filter_output(recv_index + 1, session->total_number, 
			     	POP3_MSG_ACTION_IGNORE, filter_output_data);
		    }
		}
		else /* filter_exit_code == 3 */
		{
		    e = POP3_EDELIVERY;
		    goto error_exit;
		}
	    }
	    else
	    {
		/* close pipe; check for error and update message status */
		if (delivery->close(delivery, errstr) != DELIVERY_EOK)
		{
		    e = POP3_EDELIVERY;
		    goto error_exit;
		}
		else
		{
		    if (!session->is_old[recv_index])
		    {
			session->is_old[recv_index] = 1;
			session->old_number++;
		    }
		    session->msg_action[recv_index] = POP3_MSG_ACTION_DELETE;
		}
	    }
	    piped_commands--;
	}
	if (piped_commands <= pipeline_min)
	{
	    /* SEND: refill the pipe */
	    for (; send_index < session->total_number 
		    && piped_commands < pipeline_max; send_index++)
	    {
		if (session->msg_action[send_index] != POP3_MSG_ACTION_NORMAL)
		{
		    continue;
		}
		if (filter)
		{
		    e = pop3_send_cmd(session, errstr, "TOP %ld 0", 
			    send_index + 1);
		}
		else
		{
		    e = pop3_send_cmd(session, errstr, "RETR %ld", 
			    send_index + 1);
		}
		if (e != POP3_EOK)
		{
		    goto error_exit;
		}
		piped_commands++;
	    }
	}
    }
    while (piped_commands > 0);
    
    if (delivery_method_free(delivery, errstr) != DELIVERY_EOK)
    {
	delivery = NULL;
	e = POP3_EDELIVERY;
	goto error_exit;
    }

    return POP3_EOK;

error_exit:
    if (delivery)
    {
	errstr_bak = NULL;
    	(void)delivery_method_free(delivery, &errstr_bak);
	free(errstr_bak);
    }
    if (from_addr)
    {
	free(from_addr);
    }
    if (tmpf)
    {
	(void)fclose(tmpf);
    }
    return e;
}


/*
 * pop3_filter()
 *
 * see pop3.h
 */

int pop3_filter(pop3_session_t *session,
#if HAVE_SIGACTION
	volatile sig_atomic_t *abort, 
#endif
	const char *filtercmd,
	void (*filter_output)(long i, long number, int new_action, 
	    void *filter_output_data),
	void *filter_output_data, 
	char **errmsg, char **errstr)
{
    return pop3_delivery(session, 
#if HAVE_SIGACTION
	    abort, 
#endif
	    1, filter_output, filter_output_data,
	    DELIVERY_METHOD_FILTER, filtercmd, 
	    NULL, NULL, NULL, NULL, errmsg, errstr);
}


/*
 * pop3_retr()
 *
 * see pop3.h
 */

int pop3_retr(pop3_session_t *session,
#if HAVE_SIGACTION
	volatile sig_atomic_t *abort, 
#endif
	int delivery_method, const char *delivery_method_arguments,
	void (*progress_start)(long i, long number, long size),
	void (*progress)(long i, long number, long rcvd, long size, 
	    int percent),
	void (*progress_end)(long i, long number, long size),
	void (*progress_abort)(long i, long number, long size),
	char **errmsg, char **errstr)
{
    return pop3_delivery(session, 
#if HAVE_SIGACTION
	    abort, 
#endif
	    0, NULL, NULL,
	    delivery_method, delivery_method_arguments,
	    progress_start, progress, progress_end, progress_abort,
	    errmsg, errstr);
}
    

/*
 * pop3_dele()
 *
 * see pop3.h
 */

int pop3_dele(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;
    int pipeline_min;
    int pipeline_max;
    long send_index;
    long recv_index;
    int piped_commands;
    

    if (session->pipelining)
    {
	pipeline_min = POP3_PIPELINE_MIN;
	pipeline_max = POP3_PIPELINE_MAX;
    }
    else
    {
	pipeline_min = 0;
	pipeline_max = 1;
    }
    send_index = 0;
    recv_index = 0;
    piped_commands = 0;
    do 
    {
	/* RECEIVE */
	for (; recv_index < session->total_number
		&& piped_commands > (send_index < session->total_number 
		    ? pipeline_min : 0);
		recv_index++)
	{
	    if (session->msg_action[recv_index] != POP3_MSG_ACTION_DELETE)
	    {
		continue;
	    }
	    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	    {
		return e;
	    }
	    if (!pop3_msg_ok(session->buffer))
	    {
		*errmsg = xstrdup(session->buffer);
		*errstr = xasprintf(_("command DELE %ld failed"), 
			recv_index + 1);
		return POP3_EPROTO;
	    }
	    if (session->is_old[recv_index])
	    {
		session->is_old[recv_index] = 0;
		session->old_number--;
	    }
	    piped_commands--;
	}
	if (piped_commands <= pipeline_min)
	{
	    /* SEND: refill the pipe */
	    for (; send_index < session->total_number 
		    && piped_commands < pipeline_max; send_index++)
	    {
		if (session->msg_action[send_index] != POP3_MSG_ACTION_DELETE)
		{
		    continue;
		}
		if ((e = pop3_send_cmd(session, errstr, "DELE %ld", 
				send_index + 1)) != POP3_EOK)
		{
		    return e;
		}
		piped_commands++;
	    }
	}
    }
    while (piped_commands > 0);
    
    return POP3_EOK;
}


/*
 * pop3_auth_user()
 *
 * Do POP3 authentication via the USER command.
 * The POP3 server must support POP3_CAP_AUTH_USER.
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO, POP3_EAUTHFAIL
 */

int pop3_auth_user(pop3_session_t *session, 
	const char *user, const char *password, 
	char **errmsg, char **errstr)
{
    int e;
    int etmp;
    
    if (session->pipelining)
    {
	if ((e = pop3_send_cmd(session, errstr, "USER %s", user)) != POP3_EOK)
	{
	    return e;
	}
	if ((e = pop3_send_cmd(session, errstr, "PASS %s", password)) 
		!= POP3_EOK)
	{
	    return e;
	}
	if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	{
	    return e;
	}
	e = POP3_EOK;
	if (!pop3_msg_ok(session->buffer))
	{
	    *errmsg = xstrdup(session->buffer);
	    *errstr = xasprintf(_("authentication failed (method %s)"), "USER");
	    e = POP3_EAUTHFAIL;
	}
	if ((etmp = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	{
	    return etmp;
	}
	if (e == POP3_EOK)
	{
	    if (!pop3_msg_ok(session->buffer))
	    {
		*errmsg = xstrdup(session->buffer);
		*errstr = xasprintf(_("authentication failed (method %s)"),
			"USER");
		e = POP3_EAUTHFAIL;
	    }
	}
	if (e != POP3_EOK)
	{
	    return e;
	}
    }
    else
    {
	if ((e = pop3_send_cmd(session, errstr, "USER %s", user)) != POP3_EOK)
	{
	    return e;
	}
	if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (!pop3_msg_ok(session->buffer))
	{
	    *errmsg = xstrdup(session->buffer);
	    *errstr = xasprintf(_("authentication failed (method %s)"), "USER");
	    return POP3_EAUTHFAIL;
	}
	if ((e = pop3_send_cmd(session, errstr, "PASS %s", password)) 
		!= POP3_EOK)
	{
	    return e;
	}
	if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (!pop3_msg_ok(session->buffer))
	{
	    *errmsg = xstrdup(session->buffer);
	    *errstr = xasprintf(_("authentication failed (method %s)"), "USER");
	    return POP3_EAUTHFAIL;
	}
    }
    
    return POP3_EOK;
}


/*
 * pop3_auth_apop()
 *
 * Do POP3 authentication via the APOP command.
 * The POP3 server must support POP3_CAP_AUTH_APOP.
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO, POP3_EAUTHFAIL
 */

int pop3_auth_apop(pop3_session_t *session,
	const char *user, const char *password, 
	char **errmsg, char **errstr)
{
    int e;
    char *tmpstr;
    unsigned char digest[16];
    char hex[] = "0123456789abcdef";
    char digest_string[33];
    int i;
    
    tmpstr = xasprintf("%s%s", session->cap.apop_timestamp, password);
    md5_buffer(tmpstr, strlen(tmpstr), digest);
    for (i = 0; i < 16; i++)
    {
	digest_string[2 * i] = hex[(digest[i] & 0xf0) >> 4];
	digest_string[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    digest_string[32] = '\0';
    free(tmpstr);
    if ((e = pop3_send_cmd(session, errstr, "APOP %s %s", user, digest_string))
	    != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "APOP");
	return POP3_EAUTHFAIL;
    }

    return POP3_EOK;
}


/*
 * pop3_auth_plain()
 *
 * Do POP3 authentication via the SASL PLAIN method.
 * The POP3 server must support POP3_CAP_AUTH_PLAIN.
 * 'buffer' must be at least POP3_BUFSIZE characters long. buffer[0] will be 
 * '\0' unless the POP3 server sent an error message, in which case the buffer
 * contains this message. 
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO, POP3_EAUTHFAIL
 */

#ifndef HAVE_LIBGSASL
int pop3_auth_plain(pop3_session_t *session,
	const char *user, const char *password, 
	char **errmsg, char **errstr)
{
    char *tmpstr;
    char *b64;
    size_t u_len;
    size_t p_len;
    size_t b64_len;
    int e;

    u_len = strlen(user);
    p_len = strlen(password);
    tmpstr = xasprintf("%c%s%c%s", '\0', user, '\0', password);
    b64_len = BASE64_LENGTH(u_len + p_len + 2);
    b64 = xmalloc(b64_len + 1);
    base64_encode(tmpstr, u_len + p_len + 2, b64, b64_len + 1);
    free(tmpstr);
    if ((e = pop3_send_cmd(session, errstr, "AUTH PLAIN %s", b64)) != POP3_EOK)
    {
	free(b64);
	return e;
    }
    free(b64);
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "PLAIN");
	return POP3_EAUTHFAIL;
    }

    return POP3_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * pop3_auth_login()
 *
 * Do POP3 authentication via the SASL LOGIN method.
 * The POP3 server must support POP3_CAP_AUTH_LOGIN.
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO, POP3_EAUTHFAIL
 */

#ifndef HAVE_LIBGSASL
int pop3_auth_login(pop3_session_t *session,
	const char *user, const char *password, 
	char **errmsg, char **errstr)
{
    int e;
    char *b64;
    size_t b64_len;
    size_t u_len;
    size_t p_len;
    
    if ((e = pop3_send_cmd(session, errstr, "AUTH LOGIN")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 1, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "AUTH LOGIN");
	return POP3_EPROTO;
    }
    u_len = strlen(user);
    b64_len = BASE64_LENGTH(u_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(user, u_len, b64, b64_len + 1);
    if ((e = pop3_send_cmd(session, errstr, "%s", b64)) != POP3_EOK)
    {
	free(b64);
	return e;
    }
    free(b64);
    if ((e = pop3_get_msg(session, 1, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "LOGIN");
	return POP3_EAUTHFAIL;
    }
    p_len = strlen(password);
    b64_len = BASE64_LENGTH(p_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(password, p_len, b64, b64_len + 1);
    if ((e = pop3_send_cmd(session, errstr, "%s", b64)) != POP3_EOK)
    {
	free(b64);
	return e;
    }
    free(b64);
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "LOGIN");
	return POP3_EAUTHFAIL;
    }

    return POP3_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * pop3_auth_cram_md5()
 *
 * Do POP3 authentication via the SASL CRAM-MD5 method.
 * The POP3 server must support POP3_CAP_AUTH_CRAM_MD5.
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO, POP3_EAUTHFAIL, 
 * POP3_ELIBFAILED
 */

#ifndef HAVE_LIBGSASL
int pop3_auth_cram_md5(pop3_session_t *session,
	const char *user, const char *password, 
	char **errmsg, char **errstr)
{
    unsigned char digest[16];
    char hex[] = "0123456789abcdef";
    char *challenge;
    size_t challenge_len;
    char *b64;
    size_t b64_len;
    char *buf;
    char *p;
    size_t len;
    int i;
    int e;
    
    if ((e = pop3_send_cmd(session, errstr, "AUTH CRAM-MD5")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 1, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "AUTH CRAM-MD5");
	return POP3_EPROTO;
    }
    /* we know the line is at least 4 characters long */
    challenge = session->buffer + 2;
    challenge_len = strlen(challenge);
    len = 3 * (challenge_len / 4) + 2;
    b64 = xmalloc(len);
    if (!base64_decode(challenge, challenge_len, b64, &len))
    {
	*errstr = xasprintf(_("authentication method CRAM-MD5: "
		    "server sent invalid challenge"));
	return POP3_EPROTO;
    }
    hmac_md5(password, strlen(password), b64, len, digest);
    free(b64);
    
    /* construct username + ' ' + digest_in_hex */
    len = (int)strlen(user);
    buf = xmalloc((len + 1 + 32 + 1) * sizeof(char));
    strcpy(buf, user);
    p = buf + len;
    *p++ = ' ';
    for (i = 0; i < 16; i++)
    {
	p[2 * i] = hex[(digest[i] & 0xf0) >> 4];
	p[2 * i + 1] = hex[digest[i] & 0x0f];
    }
    p[32] = '\0';
    
    b64_len = BASE64_LENGTH(len + 33);
    b64 = xmalloc(b64_len + 1);
    base64_encode(buf, len + 33, b64, b64_len + 1);
    free(buf);
    if ((e = pop3_send_cmd(session, errstr, "%s", b64)) != POP3_EOK)
    {
	free(b64);
	return e;
    }
    free(b64);
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "CRAM-MD5");
	return POP3_EAUTHFAIL;
    }

    return POP3_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * pop3_auth_external()
 * 
 * Do POP3 authentication via AUTH EXTERNAL.
 * This means the actual authentication is done via TLS; we just send the user
 * name to ther server.
 * The POP3 server must support POP3_CAP_AUTH_EXTERNAL
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EAUTHFAIL, POP3_EINVAL
 */

#ifndef HAVE_LIBGSASL
int pop3_auth_external(pop3_session_t *session, const char *user, 
	char **errmsg, char **errstr)
{
    size_t u_len;
    size_t b64_len;
    char *b64;
    int e;

    if ((e = pop3_send_cmd(session, errstr, "AUTH EXTERNAL")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "AUTH EXTERNAL");
	return POP3_EPROTO;
    }
    u_len = strlen(user);
    b64_len = BASE64_LENGTH(u_len);
    b64 = xmalloc(b64_len + 1);
    base64_encode(user, u_len, b64, b64_len + 1);
    if ((e = pop3_send_cmd(session, errstr, "%s", b64)) != POP3_EOK)
    {
	free(b64);
	return e;
    }
    free(b64);
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("authentication failed (method %s)"), "EXTERNAL");
	return POP3_EAUTHFAIL;
    }

    return POP3_EOK;
}
#endif /* !HAVE_LIBGSASL */


/*
 * pop3_server_supports_authmech()
 *
 * see pop3.h
 */

int pop3_server_supports_authmech(pop3_session_t *session, const char *mech)
{
    return (((session->cap.flags & POP3_CAP_AUTH_USER)
   		&& strcmp(mech, "USER") == 0)
   	    || ((session->cap.flags & POP3_CAP_AUTH_APOP)
   		&& strcmp(mech, "APOP") == 0)
   	    || ((session->cap.flags & POP3_CAP_AUTH_PLAIN)
   		&& strcmp(mech, "PLAIN") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_CRAM_MD5)
		&& strcmp(mech, "CRAM-MD5") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_DIGEST_MD5)
		&& strcmp(mech, "DIGEST-MD5") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_EXTERNAL)
		&& strcmp(mech, "EXTERNAL") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_GSSAPI)
		&& strcmp(mech, "GSSAPI") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_LOGIN)
		&& strcmp(mech, "LOGIN") == 0)
	    || ((session->cap.flags & POP3_CAP_AUTH_NTLM)
		&& strcmp(mech, "NTLM") == 0));
}


/*
 * pop3_client_supports_authmech()
 *
 * see pop3.h
 */

int pop3_client_supports_authmech(const char *mech)
{
#ifdef HAVE_LIBGSASL

    int supported = 0;
    Gsasl *ctx;
    
    if (strcmp(mech, "USER") == 0 || strcmp(mech, "APOP") == 0)
    {
	supported = 1;
    }
    else
    {
     	if (gsasl_init(&ctx) != GSASL_OK)
	{
	    return 0;
	}
	supported = gsasl_client_support_p(ctx, mech);
	gsasl_done(ctx);
    }
    return supported;
    
#else /* not HAVE_LIBGSASL */
    
    return (strcmp(mech, "USER") == 0
	    || strcmp(mech, "APOP") == 0
	    || strcmp(mech, "CRAM-MD5") == 0
	    || strcmp(mech, "PLAIN") == 0
	    || strcmp(mech, "EXTERNAL") == 0
	    || strcmp(mech, "LOGIN") == 0);
    
#endif /* not HAVE_LIBGSASL */
}


/*
 * pop3_auth()
 *
 * see pop3.h
 */

int pop3_auth(pop3_session_t *session, 
	const char *auth_mech,
	const char *user, 
	const char *password, 
	const char *hostname,
#ifdef HAVE_LIBGSASL
	const char *ntlmdomain,
#else
	const char *ntlmdomain UNUSED,
#endif
	char *(*password_callback)(const char *hostname, const char *user),
	char **errmsg,
	char **errstr)
{
#ifdef HAVE_LIBGSASL
    int e = POP3_EOK;
    Gsasl *ctx;
    Gsasl_session *sctx;
    char *input;
    char *outbuf;
    int error_code;
    int auth_plain_special;
    char *callback_password = NULL;


    if (strcmp(auth_mech, "") != 0 
	    && !pop3_server_supports_authmech(session, auth_mech))
    {
	*errstr = xasprintf(
		_("POP3 server does not support authentication method %s"), 
		auth_mech);
	return POP3_EUNAVAIL;
    }
    if ((error_code = gsasl_init(&ctx)) != GSASL_OK)
    {
	*errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
	return POP3_ELIBFAILED;
    }
    if (strcmp(auth_mech, "") != 0 && !pop3_client_supports_authmech(auth_mech))
    {
	gsasl_done(ctx);
	*errstr = xasprintf(
		_("GNU SASL: authentication method %s not supported"), 
		auth_mech);
	return POP3_ELIBFAILED;
    }
    if (strcmp(auth_mech, "") == 0)
    {
	/* Choose "best" authentication mechanism. */
	/* TODO: use gsasl_client_suggest_mechanism()? */
	if (gsasl_client_support_p(ctx, "GSSAPI") 
		&& (session->cap.flags & POP3_CAP_AUTH_GSSAPI))
	{
	    auth_mech = "GSSAPI";
	}
	else if (gsasl_client_support_p(ctx, "DIGEST-MD5") 
		&& (session->cap.flags & POP3_CAP_AUTH_DIGEST_MD5))
	{
	    auth_mech = "DIGEST-MD5";
	}
	else if (gsasl_client_support_p(ctx, "CRAM-MD5") 
		&& (session->cap.flags & POP3_CAP_AUTH_CRAM_MD5))
	{
	    auth_mech = "CRAM-MD5";
	}
#ifdef HAVE_TLS
	else if (tls_is_active(&session->tls))
	{
	    if (session->cap.flags & POP3_CAP_AUTH_APOP)
	    {
		auth_mech = "APOP";
	    }
	    else if (gsasl_client_support_p(ctx, "PLAIN") 
		    && (session->cap.flags & POP3_CAP_AUTH_PLAIN))
	    {
		auth_mech = "PLAIN";
	    }
	    else if (session->cap.flags & POP3_CAP_AUTH_USER)
	    {
		auth_mech = "USER";
	    }		    
	    else if (gsasl_client_support_p(ctx, "LOGIN") 
		    && (session->cap.flags & POP3_CAP_AUTH_LOGIN))
	    {
		auth_mech = "LOGIN";
	    }
	    else if (gsasl_client_support_p(ctx, "NTLM") 
		    && (session->cap.flags & POP3_CAP_AUTH_NTLM))
	    {
		auth_mech = "NTLM";
	    }
	}
#endif /* HAVE_TLS */
    }
    if (strcmp(auth_mech, "") == 0)
    {
	gsasl_done(ctx);
#ifdef HAVE_TLS
	if (!tls_is_active(&session->tls))
	{
#endif /* HAVE_TLS */
	    *errstr = xasprintf(_("cannot use a secure authentication method"));
#ifdef HAVE_TLS
	}
	else
	{
	    *errstr = xasprintf(
		    _("cannot find a usable authentication method"));
	}
#endif /* not HAVE_TLS */
	return POP3_EUNAVAIL;
    }

    /* Check availability of required authentication data */
    if (strcmp(auth_mech, "EXTERNAL") != 0)
    {
	/* GSSAPI, DIGEST-MD5, CRAM-MD5, PLAIN, LOGIN, NTLM, USER, APOP all 
	 * need a user name */
	if (!user)
	{
	    gsasl_done(ctx);
	    *errstr = xasprintf(_("authentication method %s needs a user name"),
		    auth_mech);
	    return POP3_EUNAVAIL;
	}
	/* DIGEST-MD5, CRAM-MD5, PLAIN, LOGIN, NTLM, USER, APOP all need a 
	 * password */
	if (strcmp(auth_mech, "GSSAPI") != 0 && !password)
	{
	    if (!password_callback 
		    || !(callback_password = password_callback(hostname, user)))
	    {
		gsasl_done(ctx);
		*errstr = xasprintf(
			_("authentication method %s needs a password"),
			auth_mech);
		return POP3_EUNAVAIL;
	    }
	    password = callback_password;
	}
    }

    /* USER and APOP are built-in, all other methods are provided by GNU SASL */
    if (strcmp(auth_mech, "USER") == 0)
    {
	gsasl_done(ctx);
	e = pop3_auth_user(session, user, password, errmsg, errstr);
	free(callback_password);
	return e;
    }
    else if (strcmp(auth_mech, "APOP") == 0)
    {
	gsasl_done(ctx);
    	e = pop3_auth_apop(session, user, password, errmsg, errstr);
	free(callback_password);
	return e;
    }
    else if ((error_code = gsasl_client_start(ctx, auth_mech, &sctx)) 
	    != GSASL_OK)
    {
	gsasl_done(ctx);
	*errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
	return POP3_ELIBFAILED;
    }

    /* Set the authentication properties */
    if (user)
    {
	gsasl_property_set(sctx, GSASL_AUTHID, user);
	/* GSASL_AUTHZID must not be set for DIGEST-MD5, because otherwise
	 * authentication may fail (tested with postfix). Set it only for
	 * EXTERNAL. */
 	if (strcmp(auth_mech, "EXTERNAL") == 0)
 	{
      	    gsasl_property_set(sctx, GSASL_AUTHZID, user);
    	}
    }
    if (password)
    {
	gsasl_property_set(sctx, GSASL_PASSWORD, password);	
    }
    free(callback_password);
    /* For DIGEST-MD5 and GSSAPI */
    gsasl_property_set(sctx, GSASL_SERVICE, "pop");
    if (hostname)
    {
	gsasl_property_set(sctx, GSASL_HOSTNAME, hostname);
    }
    /* For NTLM. Postfix does not care, MS IIS needs an arbitrary non-empty
     * string. */
    if (ntlmdomain)
    {
	gsasl_property_set(sctx, GSASL_REALM, ntlmdomain);
    }

    /* Bigg authentication loop */
    input = NULL;
    do
    {
	error_code = gsasl_step64(sctx, input, &outbuf);
	if (error_code != GSASL_OK && error_code != GSASL_NEEDS_MORE)
	{
	    gsasl_finish(sctx);
	    gsasl_done(ctx);
	    *errstr = xasprintf(_("GNU SASL: %s"), gsasl_strerror(error_code));
	    return POP3_ELIBFAILED;
	}
	if (!input)
	{
	    if (strcmp(auth_mech, "PLAIN") == 0 && outbuf[0])
	    {
		/* AUTH PLAIN needs special treatment because it needs to send 
		 * the authentication data together with the AUTH PLAIN command.
		 * At least some SMTP servers require this, for example
		 * smtp.web.de, which I happen to use :) */
		auth_plain_special = 1;
		if ((e = pop3_send_cmd(session, errstr, 
				"AUTH PLAIN %s", outbuf)) != POP3_EOK)
		{
		    gsasl_finish(sctx);
		    gsasl_done(ctx);
		    free(outbuf);
		    return e;
		}
	    }
	    else
	    {	    
		auth_plain_special = 0;
		if ((e = pop3_send_cmd(session, errstr, 
				"AUTH %s", auth_mech)) != POP3_EOK)
		{
		    gsasl_finish(sctx);
		    gsasl_done(ctx);
		    free(outbuf);
		    return e;
		}
	    }
	    if ((e = pop3_get_msg(session, 1, errstr)) != POP3_EOK)
	    {
		gsasl_finish(sctx);
		gsasl_done(ctx);
	    	free(outbuf);
		return e;
	    }
	    if (!pop3_msg_ok(session->buffer))
	    {
		gsasl_finish(sctx);
		gsasl_done(ctx);
		free(outbuf);
		*errstr = xasprintf(_("authentication failed (method %s)"), 
			auth_mech);
		return POP3_EAUTHFAIL;
	    }	    
	    input = session->buffer + 2;
	    if (auth_plain_special)
	    {
		free(outbuf);
		continue;
	    }
	}
	/* For all mechanisms except GSSAPI, testing for (outbuf[0]) works.
	 * GSSAPI needs an additional step with empty output. */
	if (outbuf[0] 
		|| (GSASL_NEEDS_MORE && (strcmp(auth_mech, "GSSAPI") == 0)))
	{
	    if ((e = pop3_send_cmd(session, errstr, "%s", outbuf)) != POP3_EOK)
    	    {
		gsasl_finish(sctx);
		gsasl_done(ctx);
		free(outbuf);
		return e;
	    }
	    if ((e = pop3_get_msg(session, 1, errstr)) != POP3_EOK)
	    {
		gsasl_finish(sctx);
		gsasl_done(ctx);
		free(outbuf);
		return e;
	    }
	    if (!pop3_msg_ok(session->buffer))
	    {
		gsasl_finish(sctx);
		gsasl_done(ctx);
		free(outbuf);
		*errstr = xasprintf(_("authentication failed (method %s)"), 
			auth_mech);
		return POP3_EAUTHFAIL;
	    }	    
	    input = session->buffer + 2;
	}
	free(outbuf);
    }
    while (error_code == GSASL_NEEDS_MORE);
    if (error_code != GSASL_OK)
    {
	gsasl_finish(sctx);
	gsasl_done(ctx);
	*errstr = xasprintf(_("authentication failed: %s (method %s)"), 
		gsasl_strerror(error_code), auth_mech);
	return POP3_EAUTHFAIL;
    }
    gsasl_finish(sctx);
    gsasl_done(ctx);
    /* For DIGEST-MD5, we need to send an empty answer to the last 334 
     * response before we get 235. */
    if (strcmp(auth_mech, "DIGEST-MD5") == 0)
    {
	if ((e = pop3_send_cmd(session, errstr, "")) != POP3_EOK)
	{
	    return e;
	}
	if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
	{
	    return e;
	}
	if (!pop3_msg_ok(session->buffer))
	{
	    *errmsg = xstrdup(session->buffer);
	    *errstr = xasprintf(_("authentication failed (method %s)"),
		    auth_mech);
	    return POP3_EAUTHFAIL;
	}
    }
    return POP3_EOK;

#else /* not HAVE_LIBGSASL */

    char *callback_password = NULL;
    int e;
    
    
    if (strcmp(auth_mech, "") != 0 
	    && !pop3_server_supports_authmech(session, auth_mech))
    {
	*errstr = xasprintf( 
		_("POP3 server does not support authentication method %s"), 
		auth_mech);
	return POP3_EUNAVAIL;
    }
    /* Choose "best" authentication mechanism. */
    if (strcmp(auth_mech, "") == 0)
    {
	if (session->cap.flags & POP3_CAP_AUTH_CRAM_MD5)
	{
	    auth_mech = "CRAM-MD5";
	}
	else if (session->cap.flags & POP3_CAP_AUTH_APOP)
	{
	    auth_mech = "APOP";
	}
#ifdef HAVE_TLS
	else if (tls_is_active(&session->tls))
	{
	    if (session->cap.flags & POP3_CAP_AUTH_PLAIN)
	    {
		auth_mech = "PLAIN";
	    }
	    else if (session->cap.flags & POP3_CAP_AUTH_USER)
	    {
		auth_mech = "USER";
	    }
	    else if (session->cap.flags & POP3_CAP_AUTH_LOGIN)
	    {
		auth_mech = "LOGIN";
	    }
	}
#endif /* HAVE_TLS */
    }
    if (strcmp(auth_mech, "") == 0)
    {
#ifdef HAVE_TLS
	if (!tls_is_active(&session->tls))
	{
#endif /* HAVE_TLS */
	    *errstr = xasprintf(_("cannot use a secure authentication method"));
#ifdef HAVE_TLS
	}
	else
	{
	    *errstr = xasprintf(
		    _("cannot find a usable authentication method"));
	}
#endif /* not HAVE_TLS */
	return POP3_EUNAVAIL;
    }
    
    /* Check availability of required authentication data */
    if (strcmp(auth_mech, "EXTERNAL") != 0)
    {
	/* CRAM-MD5, PLAIN, LOGIN, APOP, USER all need a user name and 
	 * password */
	if (!user)
	{
	    *errstr = xasprintf(_("authentication method %s needs a user name"),
		    auth_mech);
	    return POP3_EUNAVAIL;
	}
	if (!password)
	{
	    if (!password_callback 
		    || !(callback_password = password_callback(hostname, user)))
	    {
		*errstr = xasprintf(
			_("authentication method %s needs a password"),
			auth_mech);
		return POP3_EUNAVAIL;
	    }
	    password = callback_password;
	}
    }

    if (strcmp(auth_mech, "USER") == 0)
    {
	e = pop3_auth_user(session, user, password, errmsg, errstr);
    }
    else if (strcmp(auth_mech, "APOP") == 0)
    {
	e = pop3_auth_apop(session, user, password, errmsg, errstr);
    }
    else if (strcmp(auth_mech, "CRAM-MD5") == 0)
    {
	e = pop3_auth_cram_md5(session, user, password, errmsg, errstr);
    }
    else if (strcmp(auth_mech, "PLAIN") == 0)
    {
	e = pop3_auth_plain(session, user, password, errmsg, errstr);
    }
    else if (strcmp(auth_mech, "EXTERNAL") == 0)
    {
	e = pop3_auth_external(session, user ? user : "", errmsg, errstr);
    }
    else if (strcmp(auth_mech, "LOGIN") == 0)
    {
	e = pop3_auth_login(session, user, password, errmsg, errstr);
    }
    else
    {
	*errstr = xasprintf(_("authentication method %s not supported"),
		auth_mech);
	e = POP3_ELIBFAILED;
    }
    free(callback_password);
    return e;

#endif /* not HAVE_LIBGSASL */
}


/*
 * pop3_rset()
 *
 * see pop3.h
 */

int pop3_rset(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;

    if ((e = pop3_send_cmd(session, errstr, "RSET")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "RSET");
	return POP3_EPROTO;
    }
    return POP3_EOK;
}


/*
 * pop3_quit()
 *
 * see pop3.h
 */

int pop3_quit(pop3_session_t *session, char **errmsg, char **errstr)
{
    int e;
    
    if ((e = pop3_send_cmd(session, errstr, "QUIT")) != POP3_EOK)
    {
	return e;
    }
    if ((e = pop3_get_msg(session, 0, errstr)) != POP3_EOK)
    {
	return e;
    }
    if (!pop3_msg_ok(session->buffer))
    {
	*errmsg = xstrdup(session->buffer);
	*errstr = xasprintf(_("command %s failed"), "QUIT");
	return POP3_EPROTO;
    }
    return POP3_EOK;
}

    
/*
 * pop3_close()
 *
 * see pop3.h
 */

void pop3_close(pop3_session_t *session)
{
#ifdef HAVE_TLS
    if (tls_is_active(&session->tls))
    {
	tls_close(&session->tls);
    }
#endif /* HAVE_TLS */
    net_close_socket(session->fd);
}
