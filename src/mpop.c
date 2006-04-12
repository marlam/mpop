/*
 * mpop.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
extern int errno;
#include <time.h>
#include <getopt.h>
extern char *optarg;
extern int optind;
#ifdef ENABLE_NLS
#include <locale.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SIGACTION
#include <signal.h>
#endif
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#include <windows.h>
#include <winsock2.h>
#elif defined DJGPP
#include <io.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#else /* UNIX */
#include <netdb.h>
#include <arpa/inet.h>
#endif
#include <sysexits.h>

#include "getpass.h"
#include "gettext.h"
#include "xalloc.h"
#include "xvasprintf.h"

#include "list.h"
#include "os_env.h"
#include "conf.h"
#include "net.h"
#include "netrc.h"
#include "delivery.h"
#include "pop3.h"
#ifdef HAVE_SSL
#include "tls.h"
#endif /* HAVE_SSL */
#include "uidls.h"

/* Default file names. */
#ifdef _WIN32
#define CONFFILE	"mpoprc.txt"
#define UIDLSFILE	"mpop_uidls.txt"
#define NETRCFILE	"netrc.txt"
#elif defined (DJGPP)
#define CONFFILE	"_mpoprc"
#define UIDLSFILE	"_uidls"
#define NETRCFILE	"_netrc"
#else /* UNIX */
#define CONFFILE	".mpoprc"
#define UIDLSFILE	".mpop_uidls"
#define NETRCFILE	".netrc"
#endif


/* The name of this program */
const char *prgname;


/* 
 * Die if memory allocation fails
 */

void xalloc_die(void)
{
    fprintf(stderr, _("%s: FATAL: %s"), prgname, strerror(ENOMEM));
    exit(EX_OSERR);
}


/*
 * Translate error codes from net.h, tls.h, pop3.h or uidls.h
 * to error codes from sysexits.h
 */

int exitcode_net(int net_error_code)
{
    switch (net_error_code)
    {
	case NET_EHOSTNOTFOUND:
	    return EX_NOHOST;

	case NET_ESOCKET:
	    return EX_OSERR;

	case NET_ECONNECT:
	    return EX_TEMPFAIL;	    

	case NET_EIO:
	    return EX_IOERR;
	    
	case NET_ELIBFAILED:
	default:
	    return EX_SOFTWARE;
    }
}

#ifdef HAVE_SSL
int exitcode_tls(int tls_error_code)
{
    switch (tls_error_code)
    {
	case TLS_EIO:
	    return EX_IOERR;

	case TLS_EFILE:
	    return EX_NOINPUT;

	case TLS_EHANDSHAKE:
	    return EX_PROTOCOL;

	case TLS_ECERT:
	    /* did not find anything better... */
	    return EX_UNAVAILABLE;

	case TLS_ELIBFAILED:
	case TLS_ESEED:
	default:
	    return EX_SOFTWARE;
    }
}
#endif /* HAVE_SSL */

int exitcode_pop3(int pop3_error_code)
{
    switch (pop3_error_code)
    {
	case POP3_EIO:
	case POP3_EDELIVERY:
	    return EX_IOERR;

	case POP3_EPROTO:
	    return EX_PROTOCOL;

	case POP3_EINVAL:
	    return EX_DATAERR;

	case POP3_EAUTHFAIL:
	    return EX_NOPERM;

	case POP3_EINSECURE:
	case POP3_EUNAVAIL:
	    return EX_UNAVAILABLE;

	case POP3_ELIBFAILED:
	default:
	    return EX_SOFTWARE;
    }
}

int exitcode_uidls(int uidls_error_code)
{
    switch (uidls_error_code)
    {
	case UIDLS_EIO:
	    return EX_IOERR;
		
	case UIDLS_EFORMAT:
    	    return EX_DATAERR;

	default:
	    return EX_SOFTWARE;
    }
}

    
/*
 * mpop_sanitize_string()
 *
 * Replaces all control characters in the string with a question mark
 */

char *mpop_sanitize_string(char *str)
{
    char *p = str;
    
    while (*p != '\0')
    {
	if (iscntrl((unsigned char)*p))
	{
    	    *p = '?';
	}
	p++;
    }

    return str;
}


/*
 * mpop_password_callback()
 *
 * This function will be called by smtp_auth() to get a password if none was
 * given. It reads a password with getpass()
 * It must return NULL on failure or a password in an allocated buffer.
 */

char *mpop_password_callback(const char *hostname, const char *user)
{
    char *homedir;
    char *netrc_filename;
    netrc_entry *netrc_hostlist;
    netrc_entry *netrc_host;
    char *prompt;
    char *gpw;
    char *password = NULL;

    homedir = get_homedir();
    netrc_filename = get_filename(homedir, NETRCFILE);
    free(homedir);
    if ((netrc_hostlist = parse_netrc(netrc_filename)))
    {
	if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
	{
	    password = xstrdup(netrc_host->password);
	}
	free_netrc_entry_list(netrc_hostlist);
    }
    free(netrc_filename);
    
    if (!password)
    {
	prompt = xasprintf(_("password for %s at %s: "), user, hostname);
	gpw = getpass(prompt);
	free(prompt);
	if (gpw)
	{
	    password = xstrdup(gpw);
	}
    }
    
    return password;
}
			    
			    
/*
 * mpop_print_tls_cert_info()
 *
 * Prints information about a TLS certificate.
 */

#ifdef HAVE_SSL
/* Convert the given time into a string. */
void mpop_time_to_string(time_t *t, char *buf, size_t bufsize)
{
#ifdef ENABLE_NLS
    (void)strftime(buf, bufsize, "%c", localtime(t));
#else
    char *p;
    
    (void)snprintf(buf, bufsize, "%s", ctime(t));
    if ((p = strchr(buf, '\n')))
    {
	*p = '\0';
    }
#endif
}

void mpop_print_tls_cert_info(tls_cert_info_t *tci)
{
    const char *info_fieldname[6] = { N_("Common Name"), N_("Organization"), 
	N_("Organizational unit"), N_("Locality"), N_("State or Province"), 
	N_("Country") };
    char hex[] = "0123456789ABCDEF";
    char sha1_fingerprint_string[60];
    char md5_fingerprint_string[48];
    char timebuf[128];		/* should be long enough for every locale */
    char *tmp;
    int i;
    
    for (i = 0; i < 20; i++)
    {
	sha1_fingerprint_string[3 * i] = 
	    hex[(tci->sha1_fingerprint[i] & 0xf0) >> 4];
	sha1_fingerprint_string[3 * i + 1] = 
	    hex[tci->sha1_fingerprint[i] & 0x0f];
	sha1_fingerprint_string[3 * i + 2] = ':';
    }
    sha1_fingerprint_string[59] = '\0';
    for (i = 0; i < 16; i++)
    {
	md5_fingerprint_string[3 * i] = 
	    hex[(tci->md5_fingerprint[i] & 0xf0) >> 4];
	md5_fingerprint_string[3 * i + 1] = 
	    hex[tci->md5_fingerprint[i] & 0x0f];
	md5_fingerprint_string[3 * i + 2] = ':';
    }
    md5_fingerprint_string[47] = '\0';
    
    printf(_("TLS certificate information:\n"));
    printf("    %s:\n", _("Owner"));
    for (i = 0; i < 6; i++)
    {
	if (tci->owner_info[i])
	{
	    tmp = xstrdup(tci->owner_info[i]);
	    printf("        %s: %s\n", gettext(info_fieldname[i]), 
		    mpop_sanitize_string(tmp));
	    free(tmp);
	}
    }
    printf("    %s:\n", _("Issuer"));
    for (i = 0; i < 6; i++)
    {
	if (tci->issuer_info[i])
	{
	    tmp = xstrdup(tci->issuer_info[i]);
	    printf("        %s: %s\n", gettext(info_fieldname[i]), 
		    mpop_sanitize_string(tmp));
	    free(tmp);
	}
    }
    printf("    %s:\n", _("Validity"));
    mpop_time_to_string(&tci->activation_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Activation time"), timebuf);
    mpop_time_to_string(&tci->expiration_time, timebuf, sizeof(timebuf));
    printf("        %s: %s\n", _("Expiration time"), timebuf);
    printf("    %s:\n", _("Fingerprints"));
    printf("        SHA1: %s\n", sha1_fingerprint_string);
    printf("        MD5:  %s\n", md5_fingerprint_string);
}
#endif


/*
 * mpop_endsession()
 *
 * 1. Send QUIT if 'quit' is set
 * 2. Close connection
 * 3. Free 'session'
 */

void mpop_endsession(pop3_session_t *session, int quit)
{
    char *errmsg = NULL;
    char *errstr = NULL;
    
    if (quit)
    {
	(void)pop3_quit(session, &errmsg, &errstr);
	free(errmsg);
	free(errstr);
    }
    pop3_close(session);
    pop3_session_free(session);
}


/*
 * mpop_serverinfo()
 *
 * Prints information about the POP3 server specified in the account 'acc'.
 * If an error occured, '*errstr' points to an allocated string that descibes
 * the error or is NULL, and '*errmsg' points to the offending messages from 
 * the POP3 server or is NULL.
 */

int mpop_serverinfo(account_t *acc, int debug, char **errmsg, char **errstr)
{
    pop3_session_t *session;
    char server_greeting[POP3_BUFSIZE - 4];
#ifdef HAVE_SSL
    tls_cert_info_t *tci = NULL;
#endif /* HAVE_SSL */
    const char *server_canonical_name;
    const char *server_address;
    int auth_successful;
    int e;
    
    
    /* Create a new pop3_server_t. We won't actually retrieve any mail, so the
     * FQDN and the local user are meaningless. */
    session = pop3_session_new(acc->pipelining, "", "", debug ? stdout : NULL);

    /* connect */
    if ((e = pop3_connect(session, acc->host, acc->port, acc->timeout, 
		    &server_canonical_name, &server_address, errstr)) 
	    != NET_EOK)
    {
	pop3_session_free(session);
	e = exitcode_net(e);
	goto error_exit;
    }

    /* prepare tls */
#ifdef HAVE_SSL
    if (acc->tls)
    {
	tci = tls_cert_info_new();
	if ((e = pop3_tls_init(session, acc->tls_key_file, acc->tls_cert_file, 
			acc->tls_trust_file, errstr)) != TLS_EOK)
	{
	    pop3_session_free(session);
	    e = exitcode_tls(e);
	    goto error_exit;
	}
    }
#endif /* HAVE_SSL */

    /* start tls for pop3s servers */
#ifdef HAVE_SSL
    if (acc->tls && acc->tls_nostarttls)
    {
	if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci, 
			errstr)) != TLS_EOK)
	{
	    mpop_endsession(session, 0);
	    e = exitcode_tls(e);
	    goto error_exit;
	}
    }
#endif /* HAVE_SSL */

    /* get greeting */
    if ((e = pop3_get_greeting(session, server_greeting, errmsg, errstr))
	    != POP3_EOK)
    {
	mpop_endsession(session, 0);
	e = exitcode_pop3(e);
	goto error_exit;
    }

    /* get server capabilities the first time */
    if ((e = pop3_capa(session, errstr)) != POP3_EOK)
    {
	mpop_endsession(session, 0);
	e = exitcode_pop3(e);
	goto error_exit;
    }
    
    /* start tls for starttls servers */
#ifdef HAVE_SSL
    if (acc->tls && !acc->tls_nostarttls)
    {
	if ((session->cap.flags & POP3_CAP_CAPA) 
		&& !(session->cap.flags & POP3_CAP_STLS))
	{
	    *errstr = xasprintf(_("the POP3 server does not support TLS "
    			"via the STLS command"));
	    mpop_endsession(session, 0);
	    e = EX_UNAVAILABLE;
	    goto error_exit;
	}
	if ((e = pop3_tls_stls(session, errmsg, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    e = exitcode_pop3(e);
	    goto error_exit;
	}
	if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci, 
			errstr)) != TLS_EOK)
	{
	    mpop_endsession(session, 0);
	    e = exitcode_tls(e);
	    goto error_exit;
	}
	/* get capabilities again */
	if ((session->cap.flags & POP3_CAP_CAPA) 
		&& (e = pop3_capa(session, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    e = exitcode_pop3(e);
	    goto error_exit;
	}
    }
#endif /* HAVE_SSL */

    /* authenticate */
    auth_successful = 0;
    if ((e = pop3_auth(session, acc->auth_mech, acc->username, 
		    acc->password, acc->host, acc->ntlmdomain, 
		    mpop_password_callback, errmsg, errstr))
	    != POP3_EOK)
    {
	if (e == POP3_EIO || e == POP3_EINVAL || e == POP3_EPROTO 
		|| e == POP3_ELIBFAILED)
	{
	    mpop_endsession(session, 0);
	    e = exitcode_pop3(e);
	    goto error_exit;
	}
	/* ignore other errors, but later print a message about it */
	free(*errstr);
	*errstr = NULL;
	free(*errmsg);
	*errmsg = NULL;
    }
    else
    {
	auth_successful = 1;
    }
    
    /* Get capabilities again, because some might have changed after
     * authentication. See RFC 2449. */
    if (auth_successful 
	    && (session->cap.flags & POP3_CAP_CAPA)
	    && (e = pop3_capa(session, errstr)) != POP3_EOK)
    {
	mpop_endsession(session, 0);
	e = exitcode_pop3(e);
	goto error_exit;
    }
    
    /* print results */
    if (server_canonical_name && server_address)
    {
	printf(_("POP3 server at %s (%s [%s]), port %d:\n"), 
		acc->host, server_canonical_name, server_address, acc->port);
    }
    else if (server_canonical_name)
    {
	printf(_("POP3 server at %s (%s), port %d:\n"), 
		acc->host, server_canonical_name, acc->port);
    }
    else if (server_address)
    {
	printf(_("POP3 server at %s ([%s]), port %d:\n"), 
		acc->host, server_address, acc->port);
    }
    else
    {
	printf(_("POP3 server at %s, port %d:\n"), acc->host, acc->port);
    }
    if (*server_greeting != '\0')
    {
	printf("    %s\n", mpop_sanitize_string(server_greeting));
    }
#ifdef HAVE_SSL
    if (acc->tls)
    {
	mpop_print_tls_cert_info(tci);
    }
#endif /* not HAVE_SSL */
    printf(_("POP3 capabilities:\n"));
    if (session->cap.flags & POP3_CAP_CAPA)
    {
	printf("    CAPA:\n        %s\n", 
		_("Support for the CAPA command (get list of capabilities)"));
    }
    if (session->cap.flags & POP3_CAP_IMPLEMENTATION)
    {
	printf("    IMPLEMENTATION:\n        %s\n", 
		mpop_sanitize_string(session->cap.implementation));
    }
    if (session->cap.flags & POP3_CAP_PIPELINING)
    {
	printf("    PIPELINING:\n        %s\n",
		_("Support for command grouping for faster transmission"));
    }
    if (session->cap.flags & POP3_CAP_TOP)
    {
	printf("    TOP:\n        %s\n", 
		_("Support for the TOP command (get mail headers)"));
    }
    if (session->cap.flags & POP3_CAP_UIDL)
    {
	printf("    UIDL:\n        %s\n", 
		_("Support for the UIDL command "
		    "(get unique mail identifiers)"));
    }
    if (session->cap.flags & POP3_CAP_LOGIN_DELAY)
    {
	printf("    LOGIN-DELAY %ld:\n        ",
		session->cap.login_delay);
	printf(_("minimum time between logins is %ld seconds"), 
		session->cap.login_delay);
	if (session->cap.login_delay > 60 * 60)
	{
	    printf(_(" = %.2f hours"), 
		    (float)session->cap.login_delay / (60.0 * 60.0));
	}
	else if (session->cap.login_delay > 60)
	{
	    printf(_(" = %.2f minutes"), 
		    (float)session->cap.login_delay / 60.0);
	}
	printf("\n");
    }
    if (session->cap.flags & POP3_CAP_EXPIRE)
    {
	printf("    EXPIRE ");
	if (session->cap.expire == LONG_MAX)
	{
	    printf("NEVER:\n        %s\n", 
		    _("this POP3 server will never delete mails"));
	}
	else if (session->cap.expire == 0)
	{
	    printf("0:\n        %s\n", 
		    _("this POP3 server will not keep mails"));
	}
	else
	{
	    printf("%ld:\n        ", session->cap.expire);
	    printf(_("this POP3 server will keep mails for %ld days"),
		    session->cap.expire);
	    printf("\n");
	}
    }
#ifdef HAVE_SSL
    if ((acc->tls && !acc->tls_nostarttls) 
	    || (session->cap.flags & POP3_CAP_STLS))
#else
    if (session->cap.flags & POP3_CAP_STLS)
#endif /* not HAVE_SSL */
    {
	printf("    STLS:\n        %s\n", 
		_("Support for TLS encryption via the STLS command"));
    }
    printf("    AUTH:\n        %s\n        ", 
	    _("Supported authentication methods:"));
    if (session->cap.flags & POP3_CAP_AUTH_USER)
    {
	printf("USER ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_APOP)
    {
	printf("APOP ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_PLAIN)
    {
	printf("PLAIN ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_CRAM_MD5)
    {
	printf("CRAM-MD5 ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_DIGEST_MD5)
    {
	printf("DIGEST-MD5 ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_GSSAPI)
    {
	printf("GSSAPI ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_EXTERNAL)
    {
	printf("EXTERNAL ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_LOGIN)
    {
	printf("LOGIN ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_NTLM)
    {
	printf("NTLM ");
    }
    printf("\n");
    if (session->cap.flags & POP3_CAP_RESP_CODES)
    {
	printf("    RESP-CODES:\n        %s\n", 
		_("Server error messages in square brackets "
		    "have a special meaning"));
    }
    if (session->cap.flags & POP3_CAP_AUTH_RESP_CODE)
    {
	printf("    AUTH-RESP-CODE:\n        %s\n", 
		_("Server error messages in square brackets "
		    "have a special meaning"));
    }
#ifdef HAVE_SSL
    if ((session->cap.flags & POP3_CAP_STLS) && !acc->tls)
#else
    if (session->cap.flags & POP3_CAP_STLS)
#endif /* not HAVE_SSL */
    {
	printf(_("This server might advertise more or other capabilities\n"
    		    "    when TLS is active.\n"));
    }
    if (!auth_successful)
    {
	printf(_("This server might advertise more or other capabilities\n"
    		    "    after successful authentication.\n"));
    }
    if (!(session->cap.flags & POP3_CAP_CAPA))
    {
	printf(_("This server does not support the CAPA command, so this\n"
    		    "    list is probably not complete.\n"));
    }

    /* end session */
    mpop_endsession(session, 1);

    e = EX_OK;

error_exit:
#ifdef HAVE_SSL
    if (tci)
    {
	tls_cert_info_free(tci);
    }
#endif /* HAVE_SSL */
    return e;
}


/*
 * mpop_hr_size()
 *
 * Prints the size argument in human readable form into an allocated string.
 * Returns a pointer to this string.
 */

char *mpop_hr_size(long size)
{
    char *s;
    
    if (size >= 1024 * 1024 * 1024)
    {
	s = xasprintf(_("%.2f GB"), (float)size / (float)(1024 * 1024 * 1024));
    }
    else if (size >= 1024 * 1024)
    {
	s = xasprintf(_("%.2f MB"), (float)size / (float)(1024 * 1024));
    }
    else if (size >= 1024)
    {
	s = xasprintf(_("%.2f KB"), (float)size / 1024.0);
    }
    else if (size > 1 || size == 0)
    {
	s = xasprintf(_("%ld bytes"), size);
    }
    else
    {
	s = xasprintf(_("1 byte"));
    }

    return s;
}


/* 
 * Progress output functions for filtering and mail retrieval
 */

void mpop_filter_output(long i, long number, int new_action, void *data)
{
    if (new_action == POP3_MSG_ACTION_DELETE)
    {
	if (((account_t *)data)->keep)
	{
	    printf(_("skipping message %ld of %ld (reason: filter + keep)\n"),
		    i, number);
	}
	else
	{
	    printf(_("deleting message %ld of %ld (reason: filter)\n"), 
		    i, number);
	}
    }
    else
    {
	printf(_("skipping message %ld of %ld (reason: filter)\n"), i, number);
    }
}

void mpop_retr_progress_start(long i, long number, long size)
{
    char *sizestr = mpop_hr_size(size);
    printf(_("retrieving message %ld of %ld (%s): "), 
	    i, number, sizestr);
    free(sizestr);
    printf("  0%%\b\b\b\b");
    fflush(stdout);
}

void mpop_retr_progress(long i UNUSED, long number UNUSED, long rcvd UNUSED,
	long size UNUSED, int percent)
{
    printf("%3d\b\b\b", percent);
    fflush(stdout);
}

void mpop_retr_progress_end(long i UNUSED, long number UNUSED, long size UNUSED)
{
    printf("100\n");
}

void mpop_retr_progress_abort(long i UNUSED, long number UNUSED, 
	long size UNUSED)
{
    printf("\n");
}


/*
 * mpop_retrmail()
 *
 * Retrieve mail from the POP3 server specified in the account 'acc'.
 * If an error occured, '*errstr' points to an allocated string that describes
 * the error or is NULL, and '*errmsg' points to the offending messages from 
 * the POP3 server or is NULL.
 * This function will abort when the global variable mpop_retrmail_abort is set
 * to one, for example by a signal handler.
 */

int mpop_retrmail_abort = 0;
#ifdef HAVE_SIGACTION
void mpop_retrmail_signal_handler(int signum UNUSED)
{   
    mpop_retrmail_abort = 1;
}
#endif /* HAVE_SIGACTION */

int mpop_retrmail(const char *canonical_hostname, const char *local_user,
	account_t *acc, int debug, 
	int quiet, int auth_only, int status_only,
	char **errmsg, char **errstr)
{
    pop3_session_t *session;
#ifdef HAVE_SSL
    tls_cert_info_t *tci = NULL;
#endif /* HAVE_SSL */
    int e;
    long i, j;
    /* for identifying new messages: */
    list_t *uidl_list;
    uidl_t *uidl;
    int cmp;
    /* for status output: */
    char *sizestr;
    /* For errors that happen after a message is retrieved and delivered, and
     * thus after we can abort the POP3 session without caring about double
     * deliveries: */
    int late_error;
    char *late_errmsg;
    char *late_errstr;
    
    
    /* create a new pop3_server_t */
    session = pop3_session_new(acc->pipelining, canonical_hostname, local_user,
	    debug ? stdout : NULL);

    /* connect */
    if ((e = pop3_connect(session, acc->host, acc->port, acc->timeout, 
		    NULL, NULL, errstr)) != NET_EOK)
    {
	pop3_session_free(session);
	return exitcode_net(e);
    }

    /* prepare tls */
#ifdef HAVE_SSL
    if (acc->tls)
    {
	if ((e = pop3_tls_init(session, acc->tls_key_file, acc->tls_cert_file, 
			acc->tls_trust_file, errstr)) != TLS_EOK)
	{
	    pop3_session_free(session);
	    return exitcode_tls(e);
	}
    }
#endif /* HAVE_SSL */

    /* start tls for pop3s servers */
#ifdef HAVE_SSL
    if (acc->tls && acc->tls_nostarttls)
    {
	if (debug)
	{
	    tci = tls_cert_info_new();
	}
	if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci, 
			errstr)) != POP3_EOK)
	{
	    if (debug)
	    {
		tls_cert_info_free(tci);
	    }
	    mpop_endsession(session, 0);
	    return exitcode_tls(e);
	}
	if (debug)
	{
	    mpop_print_tls_cert_info(tci);
	    tls_cert_info_free(tci);
	}
    }
#endif /* HAVE_SSL */

    /* get greeting */
    if ((e = pop3_get_greeting(session, NULL, errmsg, errstr)) != POP3_EOK)
    {
	mpop_endsession(session, 0);
	return exitcode_pop3(e);
    }

    /* get server capabilities for the first time */
    if ((e = pop3_capa(session, errstr)) != POP3_EOK)
    {
	mpop_endsession(session, 0);
	return exitcode_pop3(e);
    }
    
    /* start tls for starttls servers */
#ifdef HAVE_SSL
    if (acc->tls && !acc->tls_nostarttls)
    {
	if ((session->cap.flags & POP3_CAP_CAPA) 
		&& !(session->cap.flags & POP3_CAP_STLS))
	{
	    *errstr = xasprintf(_("the POP3 server does not support TLS "
    			"via the STLS command"));
	    mpop_endsession(session, 0);
	    return EX_UNAVAILABLE;
	}
	if ((e = pop3_tls_stls(session, errmsg, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    return exitcode_pop3(e);
	}
	if (debug)
	{
	    tci = tls_cert_info_new();
	}
	if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci, 
			errstr)) != TLS_EOK)
	{
	    if (debug)
	    {
		tls_cert_info_free(tci);
	    }
	    mpop_endsession(session, 0);
	    return exitcode_tls(e);
	}
	if (debug)
	{
	    mpop_print_tls_cert_info(tci);
	    tls_cert_info_free(tci);
	}
	/* get capabilities again */
	if ((session->cap.flags & POP3_CAP_CAPA)
		&& (e = pop3_capa(session, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    return exitcode_pop3(e);
	}
    }
#endif /* HAVE_SSL */

    /* authenticate */
    if ((e = pop3_auth(session, acc->auth_mech, acc->username, 
		    acc->password, acc->host, acc->ntlmdomain, 
		    mpop_password_callback, errmsg, errstr)) 
	    != POP3_EOK)
    {
	mpop_endsession(session, 0);
	return exitcode_pop3(e);
    }
    if (auth_only)
    {
	mpop_endsession(session, 1);
	return EX_OK;
    }
    /* In theory, it is not necessary to get the capabilities again at this
     * point, because we won't use capabilities that may change between
     * AUTHENTICATION and TRANSACTION state (see RFC 2449)
     * However, as of 2005-01-17, at least pop.gmail.com violates this part of
     * the RFC by announcing the PIPELINING, UIDL, and TOP capabilities only
     * after authentication. Since UIDL and/or TOP may be needed, we need to
     * get the capabilities again... */
    if ((session->cap.flags & POP3_CAP_CAPA)
	    && ((acc->filter && !(session->cap.flags & POP3_CAP_TOP))
		|| !(session->cap.flags & POP3_CAP_UIDL)))
    {
	if ((e = pop3_capa(session, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    return exitcode_pop3(e);
	}
    }

    /* get status and scan listing */
    if ((e = pop3_stat(session, errmsg, errstr)) != POP3_EOK)
    {
	mpop_endsession(session, 0);
	return exitcode_pop3(e);
    }
    if (session->total_number > 0)
    {
	if ((e = pop3_list(session, errmsg, errstr)) != POP3_EOK)
	{
	    mpop_endsession(session, 0);
	    return exitcode_pop3(e);
	}
    }
    
    if (mpop_retrmail_abort)
    {
	mpop_endsession(session, 0);
	*errstr = xasprintf(_("operation aborted"));
	return EX_TEMPFAIL;
    }

    /* retrieve the UIDs */
    if (session->total_number > 0)
    {
	if ((session->cap.flags & POP3_CAP_CAPA) 
		&& !(session->cap.flags & POP3_CAP_UIDL))
	{
	    /* the POP3 server does not support UIDL */
	}
	else if ((e = pop3_uidl(session, errmsg, errstr)) != POP3_EOK)
	{
	    if (e != POP3_EPROTO)
	    {
		mpop_endsession(session, 0);
		return exitcode_pop3(e);
	    }
	    else
	    {
		/* the POP3 server does not support UIDL */
	    }
	}
    }

    /* Load the list of UID lists (if the file does not exist, the returned
     * list will be empty) */
    if ((e = uidls_read(acc->uidls_file, &uidl_list, errstr)) 
	    != UIDLS_EOK)
    {
	mpop_endsession(session, 0);
	return exitcode_uidls(e);
    }
    /* Pick the UID list for this user@host. If it does not exist, create an
     * empty one. */
    if (!(uidl = find_uidl(uidl_list, acc->host, acc->username)))
    {
	uidl = uidl_new(acc->host, acc->username);
	list_insert(uidl_list, uidl);
    }

    /* Identify new messages. Both the list of current UIDs from the POP3
     * server (accessed with session->msg_uid[session_uids_sorted[i]]) and the
     * list of already seen UIDs (accessed with uidl->uidv[j]) are sorted. */
    if (session->total_number > 0)
    {
	session->new_number = 0;
	session->new_size = 0;
	j = 0;
	i = 0;
	while (i < session->total_number)
	{
	    if (j < uidl->n)
	    {
		cmp = strcmp(uidl->uidv[j], 
			session->msg_uid[session->uids_sorted[i]]);
	    }
	    else
	    {
		cmp = +1;
	    }
	    if (cmp < 0)
	    {
		j++;
	    }
	    else if (cmp > 0)
	    {
		session->new_number++;
		session->new_size += 
		    session->msg_size[session->uids_sorted[i]];
		i++;
	    }
	    else
	    {
		/* Set action to DELETE if we should retrieve only new messages.
		 * Else leave it as NORMAL. */
		if (acc->only_new)
		{
		    session->msg_action[session->uids_sorted[i]] = 
			POP3_MSG_ACTION_DELETE;
		}
		session->is_old[session->uids_sorted[i]] = 1;
		session->old_number++;
		i++;
		j++;
	    }
	}
    }
    
    /* Print status */
    if (!quiet)
    {
	printf(_("%s at %s:\n"), acc->username, acc->host);
	if (session->total_number > 0)
	{
	    printf(_("new: "));
	    if (session->new_number == 0)
	    {
		printf(_("no messages"));
	    }
	    else if (session->new_number == 1)
	    {
		printf(_("1 message"));
	    }
	    else
	    {
		printf(_("%ld messages"), session->new_number);
	    }
	    if (session->new_number > 0)
	    {
		sizestr = mpop_hr_size(session->new_size);
		printf(_(" in %s"), sizestr);
		free(sizestr);
	    }
	    printf(", ");
	    printf(_("total: "));
	}
	if (session->total_number == 0)
    	{
	    printf(_("no messages"));
	}
	else if (session->total_number == 1)
	{
    	    printf(_("1 message"));
	}
	else
	{
	    printf(_("%ld messages"), session->total_number);
	}
	if (session->total_number > 0)
	{
	    sizestr = mpop_hr_size(session->total_size);
	    printf(_(" in %s"), sizestr);
	    free(sizestr);
	}
	printf("\n");
    }
    if (status_only)
    {
	if (uidl_list)
	{
	    list_xfree(uidl_list, uidl_free);
	}
	mpop_endsession(session, 1);
	return EX_OK;
    }

    /* Size filtering */
    if (session->total_number > 0 && (acc->killsize >= 0 || acc->skipsize >= 0))
    {
	for (i = 1; i <= session->total_number; i++)
	{
	    if (session->msg_action[i - 1] != POP3_MSG_ACTION_NORMAL)
	    {
		continue;
	    }
	    if (acc->killsize >= 0 && session->msg_size[i - 1] >= acc->killsize)
	    {
		session->msg_action[i - 1] = POP3_MSG_ACTION_DELETE;
		if (!quiet)
		{
		    if (acc->keep)
		    {
			printf(_("skipping message %ld of %ld (reason: "
    				    "killsize + keep)\n"), 
				i, session->total_number);
		    }
		    else
		    {
			printf(_("deleting message %ld of %ld (reason: "
    				    "killsize)\n"), i, session->total_number);
		    }
		}
	    }
	    else if (acc->skipsize >= 0 
		    && session->msg_size[i - 1] >= acc->skipsize)
	    {
		session->msg_action[i - 1] = POP3_MSG_ACTION_IGNORE;
		if (!quiet)
		{
		    printf(_("skipping message %ld of %ld (reason: "
    				"skipsize)\n"), i, session->total_number);
		}
	    }
	}
    }

    if (mpop_retrmail_abort)
    {
	if (uidl_list)
	{
	    list_xfree(uidl_list, uidl_free);
	}
	mpop_endsession(session, 0);
	*errstr = xasprintf(_("operation aborted"));
	return EX_TEMPFAIL;
    }

    /* Header filtering */
    if (session->total_number > 0 && acc->filter)
    {
	if ((session->cap.flags & POP3_CAP_CAPA) 
	    	    && !(session->cap.flags & POP3_CAP_TOP))
	{
	    *errstr = xasprintf(_("the POP3 server does not support the "
			"TOP command needed for filtering"));
	    if (uidl_list)
	    {
		list_xfree(uidl_list, uidl_free);
	    }
	    mpop_endsession(session, 1);
	    return EX_UNAVAILABLE;
	}
	if ((e = pop3_filter(session, &mpop_retrmail_abort, acc->filter, 
			quiet ? NULL : mpop_filter_output, acc,
			errmsg, errstr)) != POP3_EOK)
	{
	    if (uidl_list)
	    {
		list_xfree(uidl_list, uidl_free);
	    }
	    mpop_endsession(session, 0);
	    return exitcode_pop3(e);
	}
    }
    
    if (mpop_retrmail_abort)
    {
	if (uidl_list)
	{
	    list_xfree(uidl_list, uidl_free);
	}
	mpop_endsession(session, 0);
	*errstr = xasprintf(_("operation aborted"));
	return EX_TEMPFAIL;
    }

    /* Once pop3_retr() is called, we cannot just abort the session and forget
     * everything we've done so far, because that would mean double mail
     * deliveries. Instead, we at least have to update the UIDLs file. */
    late_error = POP3_EOK;
    late_errmsg = NULL;
    late_errstr = NULL;
    
    /* Retrieve */
    if (session->total_number > 0)
    {
	late_error = pop3_retr(session, 
		&mpop_retrmail_abort,
		acc->delivery_method, acc->delivery_args,
		quiet ? NULL : mpop_retr_progress_start,
		quiet ? NULL : mpop_retr_progress,
		quiet ? NULL : mpop_retr_progress_end,
	    	quiet ? NULL : mpop_retr_progress_abort,
    		&late_errmsg, &late_errstr);
    }
    
    /* Delete */
    if (late_error == POP3_EOK && !acc->keep)
    {
	late_error = pop3_dele(session, &late_errmsg, &late_errstr);
    }

    /* Update the UIDL: only insert UIDs of messages that are retrieved and
     * not deleted. */
    for (i = 0; i < uidl->n; i++)
    {
	free(uidl->uidv[i]);
    }
    free(uidl->uidv);
    uidl->uidv = NULL;
    uidl->n = session->old_number;
    if (uidl->n > 0)
    {
	uidl->uidv = xmalloc(uidl->n * sizeof(char *));
	j = 0;
	for (i = 0; i < session->total_number; i++)
	{
	    if (session->is_old[i])
	    {
		uidl->uidv[j++] = xstrdup(session->msg_uid[i]);
	    }
	}
    }
    /* Save the updated UIDL information */
    if ((e = uidls_write(acc->uidls_file, uidl_list, errstr)) != UIDLS_EOK)
    {
	free(late_errmsg);
    	free(late_errstr);
	list_xfree(uidl_list, uidl_free);
	mpop_endsession(session, 0);
	return exitcode_uidls(e);
    }
    list_xfree(uidl_list, uidl_free);

    /* End session */
    mpop_endsession(session, (late_error == POP3_EOK) ? 1 : 0);

    if (late_errmsg)
    {
	*errmsg = late_errmsg;
    }
    if (late_errstr)
    {
	*errstr = late_errstr;
    }
    return (late_error == POP3_EOK) ? EX_OK : exitcode_pop3(late_error);
}


/*
 * print_error()
 *
 * Print an error message
 */

/* make gcc print format warnings for this function */
#ifdef __GNUC__
void print_error(const char *format, ...) 
    __attribute__ ((format (printf, 1, 2)));
#endif

void print_error(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "%s: ", prgname);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fprintf(stderr, "\n");
}


/*
 * Construct a list of accounts from a list of account ids.
 * If there are no account ids, use the account "default".
 * account_list will be created, regardless of success or failure.
 * An error message will be printed in case of failure.
 * Used error codes: 1 = Account not found
 */

int get_account_list(const char *conffile, list_t *conffile_account_list, 
	int accountidc, char **accountidv, list_t **account_list)
{
    account_t *a;
    list_t *lp;
    int i;
    
    *account_list = list_new();
    lp = *account_list;
    if (accountidc == 0)
    {
	if (!(a = find_account(conffile_account_list, "default")))
	{
	    print_error(_("%s: no account %s"), conffile, "default");
	    return 1;
	}
	list_insert(lp, account_copy(a));
    }
    else
    {
	for (i = 0; i < accountidc; i++)
	{
	    if (!(a = find_account(conffile_account_list, accountidv[i])))
	    {
		print_error(_("%s: no account %s"), conffile, accountidv[i]);
		return 1;
	    }
	    list_insert(lp, account_copy(a));
	    lp = lp->next;
	}
    }
    return 0;
}


/*
 * The main function.
 * It returns values from sysexits.h (like sendmail does).
 */

/* long options without a corresponding short option */
#define LONGONLYOPT_VERSION 		0
#define LONGONLYOPT_HELP    		1
#define LONGONLYOPT_HOST		2
#define LONGONLYOPT_PORT		3
#define LONGONLYOPT_TIMEOUT		4
#define LONGONLYOPT_PIPELINING		5
#define LONGONLYOPT_AUTH		6
#define LONGONLYOPT_USER		7
#define LONGONLYOPT_TLS			8
#define LONGONLYOPT_TLS_TRUST_FILE	9
#define LONGONLYOPT_TLS_KEY_FILE	10
#define LONGONLYOPT_TLS_CERT_FILE	11
#define LONGONLYOPT_TLS_CERTCHECK	12
#define LONGONLYOPT_TLS_STARTTLS	13
#define LONGONLYOPT_KILLSIZE		14
#define LONGONLYOPT_SKIPSIZE		15
#define LONGONLYOPT_FILTER		16
#define LONGONLYOPT_DELIVERY		17
#define LONGONLYOPT_UIDLS_FILE		18

int main(int argc, char *argv[])
{
    /* the configuration */
    int print_version;
    int print_help;
    int print_conf;
    int debug;
    int pretend;
    int quiet;
    /* mode of operation */
    int retrmail;
    int serverinfo;
    int auth_only;
    int status_only;
    /* account information from the command line */
    account_t *cmdline_account = NULL;
    /* account information from the configuration file */
    char *conffile = NULL;
    list_t *conffile_account_list = NULL;
    /* the list of accounts */
    int accountidc;
    char **accountidv;
    list_t *account_list = NULL;
    list_t *lp;
    account_t *account;
    /* local system information */
    char *homedir;
    char *canonical_hostname;
    char *local_user;
    /* error handling */
    int error_code;
    int e;
    char *errstr;
    char *errmsg;
    /* signal handling */
#ifdef HAVE_SIGACTION
    struct sigaction signal_handler;
    struct sigaction old_sigterm_handler;
    struct sigaction old_sighup_handler;
    struct sigaction old_sigint_handler;
#endif /* HAVE_SIGACTION */
    /* misc */
    struct servent *se;	    
    int c;
    int net_lib_initialized = 0;
#ifdef HAVE_SSL
    int tls_lib_initialized = 0;
#endif /* HAVE_SSL */
    /* option handling */
    struct option options[] =
    {
	{ "version",         no_argument,       0, LONGONLYOPT_VERSION },
	{ "help",            no_argument,       0, LONGONLYOPT_HELP },
	{ "quiet",           no_argument,       0, 'q' },
 	{ "pretend",         no_argument,       0, 'P' },
  	{ "debug",           no_argument,       0, 'd' },
	{ "serverinfo",      no_argument,       0, 'S' },
	{ "file",            required_argument, 0, 'C' },
	{ "auth-only",       no_argument,       0, 'a' },
	{ "status-only",     no_argument,       0, 's' }, 
	{ "delivery",        required_argument, 0, LONGONLYOPT_DELIVERY },
	{ "uidls-file",      required_argument, 0, LONGONLYOPT_UIDLS_FILE },
	{ "only-new",        optional_argument, 0, 'n' },
	{ "keep",            optional_argument, 0, 'k' },
	{ "killsize",        required_argument, 0, LONGONLYOPT_KILLSIZE },
	{ "skipsize",        required_argument, 0, LONGONLYOPT_SKIPSIZE },
	{ "filter",          required_argument, 0, LONGONLYOPT_FILTER },
	{ "host",            required_argument, 0, LONGONLYOPT_HOST },
	{ "port",            required_argument, 0, LONGONLYOPT_PORT },
	{ "timeout",         required_argument, 0, LONGONLYOPT_TIMEOUT},
	{ "pipelining",      required_argument, 0, LONGONLYOPT_PIPELINING },
	{ "auth",            optional_argument, 0, LONGONLYOPT_AUTH },
	{ "user",            required_argument, 0, LONGONLYOPT_USER },
	{ "tls",             optional_argument, 0, LONGONLYOPT_TLS },
	{ "tls-trust-file",  required_argument, 0, LONGONLYOPT_TLS_TRUST_FILE },
	{ "tls-key-file",    required_argument, 0, LONGONLYOPT_TLS_KEY_FILE },
	{ "tls-cert-file",   required_argument, 0, LONGONLYOPT_TLS_CERT_FILE },
	{ "tls-certcheck",   optional_argument, 0, LONGONLYOPT_TLS_CERTCHECK },
	{ "tls-starttls",    optional_argument, 0, LONGONLYOPT_TLS_STARTTLS },
	{ 0, 0, 0, 0 }
    };
    
    /* Avoid the side effects of text mode interpretations on DOS systems. */
#ifdef _WIN32
    _fmode = _O_BINARY;
#elif defined DJGPP
    _fmode = O_BINARY;
#endif

    /* initialize variables that will be needed */
    errstr = NULL;
    errmsg = NULL;
    homedir = get_homedir();

    /* internationalization with gettext */
#ifdef ENABLE_NLS
    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);
#endif
    
    /* process the command line */
    prgname = get_prgname(argv[0]);
    error_code = 0;
    print_version = 0;
    print_help = 0;
    print_conf = 0;
    debug = 0;
    pretend = 0;
    quiet = 0;
    retrmail = 1;
    serverinfo = 0;
    auth_only = 0;
    status_only = 0;
    cmdline_account = account_new(NULL, NULL);
    for (;;)
    {
	c = getopt_long(argc, argv, "qPdSC:asn::k::", options, NULL);
	if (c == -1)
	{
	    break;
	}
	switch(c)
	{
	    case LONGONLYOPT_VERSION:
		print_version = 1;
		retrmail = 0;
		serverinfo = 0;
		break;

	    case LONGONLYOPT_HELP:
		print_help = 1;
		retrmail = 0;
		serverinfo = 0;
		break;

	    case 'q':
		quiet = 1;
		break;
		
  	    case 'P':
   		print_conf = 1;
		pretend = 1;
     		break;
      		
       	    case 'd':
		print_conf = 1;
	 	debug = 1;
		/* normal output would interfere with
		 * debugging output */
		quiet = 1;
	 	break;

	    case 'S':
		serverinfo = 1;
		retrmail = 0;
		break;
		
	    case 'a':
		auth_only = 1;
		break;

	    case 's':
		status_only = 1;
		break;

	    case 'C':
		free(conffile);
		conffile = xstrdup(optarg);
		break;

	    case LONGONLYOPT_HOST:
	    	free(cmdline_account->host);
    		cmdline_account->host = xstrdup(optarg);
		cmdline_account->mask |= ACC_HOST;
		break;
		
	    case LONGONLYOPT_PORT:
		cmdline_account->port = get_non_neg_int(optarg);
		if (cmdline_account->port < 1 || cmdline_account->port > 65535)
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--port");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_PORT;
		break;		
		
	    case LONGONLYOPT_TIMEOUT:
		if (is_off(optarg))
		{
		    cmdline_account->timeout = 0;
		}
		else
		{
		    cmdline_account->timeout = get_non_neg_int(optarg);
		    if (cmdline_account->timeout < 1)
		    {
			print_error(_("invalid argument %s for %s"), 
				optarg, "--timeout");
			error_code = 1;
		    }
		}
		cmdline_account->mask |= ACC_TIMEOUT;
		break;		
		
	    case LONGONLYOPT_PIPELINING:
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->pipelining = 1;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->pipelining = 0;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--pipelining");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_PIPELINING;
		break;		
		
	    case LONGONLYOPT_AUTH:
		free(cmdline_account->auth_mech);
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->auth_mech = xstrdup("");
		}
		else if (check_auth_arg(optarg) == 0)
		{
		    cmdline_account->auth_mech = xstrdup(optarg);
		}
		else
		{
		    cmdline_account->auth_mech = NULL;
		    print_error(_("invalid argument %s for %s"),
			    optarg, "--auth");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_AUTH_MECH;
		break;

	    case LONGONLYOPT_USER:
		free(cmdline_account->username);
		cmdline_account->username = 
		    (*optarg == '\0') ? NULL : xstrdup(optarg);
		cmdline_account->mask |= ACC_USERNAME;
		break;

	    case LONGONLYOPT_TLS:
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->tls = 1;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->tls = 0;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--tls");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_TLS;
		break;

	    case LONGONLYOPT_TLS_TRUST_FILE:
		free(cmdline_account->tls_trust_file);
		cmdline_account->tls_trust_file = (*optarg == '\0')
  		    ? NULL : expand_tilde(optarg);
		cmdline_account->mask |= ACC_TLS_TRUST_FILE;
		break;

	    case LONGONLYOPT_TLS_KEY_FILE:
		free(cmdline_account->tls_key_file);
		cmdline_account->tls_key_file = (*optarg == '\0')
  		    ? NULL : expand_tilde(optarg);
		cmdline_account->mask |= ACC_TLS_KEY_FILE;
		break;

	    case LONGONLYOPT_TLS_CERT_FILE:
		free(cmdline_account->tls_cert_file);
		cmdline_account->tls_cert_file = (*optarg == '\0')
  		    ? NULL : expand_tilde(optarg);
		cmdline_account->mask |= ACC_TLS_CERT_FILE;
		break;

	    case LONGONLYOPT_TLS_CERTCHECK:
	    	if (!optarg || is_on(optarg))
		{
		    cmdline_account->tls_nocertcheck = 0;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->tls_nocertcheck = 1;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--tls-certcheck");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_TLS_NOCERTCHECK;
		break;

	    case LONGONLYOPT_TLS_STARTTLS:
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->tls_nostarttls = 0;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->tls_nostarttls = 1;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--tls-starttls");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_TLS_NOSTARTTLS;
		break;

	    case 'n':
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->only_new = 1;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->only_new = 0;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--only-new");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_ONLY_NEW;
		break;

	    case 'k':
	    	if (!optarg || is_on(optarg))
    		{
		    cmdline_account->keep = 1;
		}
		else if (is_off(optarg))
		{
		    cmdline_account->keep = 0;
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--keep");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_KEEP;
		break;

	    case LONGONLYOPT_KILLSIZE:
	    	if (is_off(optarg))
    		{
		    cmdline_account->killsize = -1;
		}
		else
		{
		    if ((cmdline_account->killsize = get_size_arg(optarg)) < 0)
		    {
			print_error(_("invalid argument %s for %s"), 
				optarg, "--killsize");
			error_code = 1;
		    }
		}
		cmdline_account->mask |= ACC_KILLSIZE;
		break;

	    case LONGONLYOPT_SKIPSIZE:
	    	if (is_off(optarg))
    		{
		    cmdline_account->skipsize = -1;
		}
		else
		{
		    if ((cmdline_account->skipsize = get_size_arg(optarg)) < 0)
		    {
			print_error(_("invalid argument %s for %s"), 
				optarg, "--skipsize");
			error_code = 1;
		    }
		}
		cmdline_account->mask |= ACC_SKIPSIZE;
		break;

	    case LONGONLYOPT_FILTER:
		free(cmdline_account->filter);
		cmdline_account->filter = (*optarg == '\0') 
		    ? NULL : xstrdup(optarg);
		cmdline_account->mask |= ACC_FILTER;
		break;

	    case LONGONLYOPT_DELIVERY:
		if (strncmp(optarg, "mda,", 4) == 0)
		{
		    cmdline_account->delivery_method = DELIVERY_METHOD_MDA;
		    free(cmdline_account->delivery_args);
		    cmdline_account->delivery_args = xstrdup(optarg + 4);
		}
		else if (strncmp(optarg, "maildir,", 8) == 0)
		{
		    cmdline_account->delivery_method = DELIVERY_METHOD_MAILDIR;
		    free(cmdline_account->delivery_args);
		    cmdline_account->delivery_args = expand_tilde(optarg + 8);
		}
		else if (strncmp(optarg, "mbox,", 5) == 0)
		{
		    cmdline_account->delivery_method = DELIVERY_METHOD_MBOX;
		    free(cmdline_account->delivery_args);
		    cmdline_account->delivery_args = expand_tilde(optarg + 5);
		}
		else
		{
		    print_error(_("invalid argument %s for %s"), 
			    optarg, "--delivery");
		    error_code = 1;
		}
		cmdline_account->mask |= ACC_DELIVERY;
		break;

	    case LONGONLYOPT_UIDLS_FILE:
		free(cmdline_account->uidls_file);
		cmdline_account->uidls_file = expand_tilde(optarg);
		cmdline_account->mask |= ACC_UIDLS_FILE;
		break;

	    default:
		error_code = 1;
		break;
	}
	if (error_code)
	{
	    break;
	}
    }
    if (error_code)
    {
	error_code = EX_USAGE;
	goto exit;
    }

    if (print_version)
    {
	printf(_("%s version %s\n"), PACKAGE_NAME, VERSION);
	/* TLS/SSL support */
	printf(_("TLS/SSL library: %s\n"),
#ifdef HAVE_GNUTLS
		"GnuTLS"
#elif defined (HAVE_OPENSSL)
		"OpenSSL"
#else
		_("none")
#endif
	      );
	/* Authentication support */
	printf(_("Authentication library: %s\n"
		    "Supported authentication methods:\n"),
#ifdef USE_GSASL
		_("GNU SASL; user and apop: built-in")
#else
		_("built-in")
#endif /* USE_GSASL */
	      );
	if (pop3_client_supports_authmech("USER"))
	{
	    printf("user ");
	}
	if (pop3_client_supports_authmech("APOP"))
	{
	    printf("apop ");
	}
	if (pop3_client_supports_authmech("PLAIN"))
	{
	    printf("plain ");
	}
	if (pop3_client_supports_authmech("CRAM-MD5"))
	{
	    printf("cram-md5 ");
	}
	if (pop3_client_supports_authmech("DIGEST-MD5"))
	{
	    printf("digest-md5 ");
	}
	if (pop3_client_supports_authmech("GSSAPI"))
	{
	    printf("gssapi ");
	}
	if (pop3_client_supports_authmech("EXTERNAL"))
	{
	    printf("external ");
	}
	if (pop3_client_supports_authmech("LOGIN"))
	{
	    printf("login ");
	}
	if (pop3_client_supports_authmech("NTLM"))
	{
	    printf("ntlm ");
	}
	printf("\n");
	/* Internationalized Domain Names support */
	printf(_("IDN support: "));
#ifdef USE_LIBIDN
	printf(_("enabled"));
#else
	printf(_("disabled"));
#endif
	printf("\n");
	/* Native language support */
	printf(_("NLS: "));
#ifdef ENABLE_NLS
	printf(_("enabled"));
	printf(_(", LOCALEDIR is %s"), LOCALEDIR);
#else
	printf(_("disabled"));
#endif
	printf("\n\n");
	printf(_("Copyright (C) 2006 Martin Lambers and others.\n"
		    "This is free software; see the source for copying "
		    "conditions.  There is NO\n"
		    "warranty; not even for MERCHANTABILITY or FITNESS FOR A "
		    "PARTICULAR PURPOSE.\n"));
    }
    if (print_help)
    {
	printf(_("USAGE:\n\n"
		"Mail retrieval mode (default):\n"
		"  %s [option...] [--] account...\n"
		"  %s --host=host [option...]\n"
		"  Read mails from one ore more POP3 accounts and deliver "
			"them.\n"
		"Server information mode:\n"
		"  %s [option...] --serverinfo account...\n"
		"  %s --host=host [option...] --serverinfo\n"
		"  Print information about one or more POP3 servers.\n"
	        "\nOPTIONS:\n\n"
		"General options:\n"
		"  --version                  print version\n"
		"  --help                     print help\n"
     		"  -P, --pretend              print configuration info and "
			"exit\n"
      		"  -d, --debug                print debugging information\n"
		"Changing the mode of operation:\n"
		"  -S, --serverinfo           print information about the POP3 "
			"server\n"
	        "Configuration options:\n"
		"  -C, --file=filename        set configuration file\n"
		"  --host=hostname            set POP3 server, use only "
			"command line settings;\n"
		"                             do not use any configuration "
			"file data\n"
	        "  --port=number              set port number\n"
	        "  --timeout=(off|seconds)    set/unset network timeout in "
			"seconds\n"
		"  --pipelining=(on|off)      enable/disable POP3 pipelining "
			"for obsolete servers\n"
		"  --auth[=(on|method)]       choose the authentication "
			"method\n"
		"  --user=[username]          set/unset user name for "
			"authentication\n"
	        "  --tls[=(on|off)]           enable/disable TLS encryption\n"
		"  --tls-trust-file=[file]    set/unset trust file for TLS\n"
	        "  --tls-key-file=[file]      set/unset private key file for "
			"TLS\n"
		"  --tls-cert-file=[file]     set/unset private cert file for "
			"TLS\n"
	        "  --tls-certcheck[=(on|off)] enable/disable server "
			"certificate checks for TLS\n"
		"  --tls-starttls[=(on|off)]  enable/disable STLS for TLS\n"
	        "Options specific to mail retrieval mode:\n"
		"  -q, --quiet                do not display progress "
			"information\n"
		"  -a, --auth-only            authenticate only; do not "
			"retrieve mail\n"
		"  -s, --status-only          print account status only; do "
			"not retrieve mail\n"
		"  -n, --only-new[=(on|off)]  process only new messages\n"
	        "  -k, --keep[=(on|off)]      do not delete mails from POP3 "
			"servers\n"
		"  --killsize=(off|number)    set/unset kill size\n"
		"  --skipsize=(off|number)    set/unset skip size\n"
		"  --filter=[program]         set/unset header filter\n"
		"  --delivery=method,arg      set the mail delivery method\n"
		"  --uidls-file=filename      set file to store UIDLs\n"
		"\nReport bugs to <%s>.\n"),
		prgname, prgname, prgname, prgname, PACKAGE_BUGREPORT);
    }
    
    if (!retrmail && !serverinfo && !print_conf)
    {
	error_code = EX_OK;
	goto exit;
    }

    /* get the list of account ids from the command line */
    accountidc = argc - optind;
    accountidv = &(argv[optind]);
    if (accountidc > 0 && cmdline_account->host)
    {
	print_error(_("cannot use both --host and accounts"));
	error_code = EX_USAGE;
	goto exit;
    }

    /* get the list of accounts to use into 'account_list'. */
    if (!cmdline_account->host)
    {
	if (!conffile)
	{
	    conffile = get_filename(homedir, CONFFILE);
	}
	if ((e = get_conf(conffile, 1, &conffile_account_list, &errstr)) 
		!= CONF_EOK)
	{
	    print_error("%s: %s", conffile, mpop_sanitize_string(errstr));
	    if (e == CONF_EIO)
	    {
		error_code = EX_IOERR;
		goto exit;
	    }
	    else
	    {
		error_code = EX_CONFIG;
		goto exit;
	    }
	}
	/* construct list of accounts to be polled */
	if ((e = get_account_list(conffile, conffile_account_list, 
	    		accountidc, accountidv, &account_list)) != 0)
	{
	    /* an error message was already printed */
	    error_code = EX_CONFIG;
	    goto exit;
	}
	/* override all accounts with command line settings */
	lp = account_list;
	while (!list_is_empty(lp))
	{
	    lp = lp->next;
	    override_account(lp->data, cmdline_account);
	}
    }
    else
    {
	/* use only the command line account */
	account_list = list_new();
	list_insert(account_list, account_copy(cmdline_account));
    }
    /* OK, the accounts to use are in 'account_list'. Complete them and check
     * them */
    lp = account_list;
    while (!list_is_empty(lp))
    {
	lp = lp->next;
	account = lp->data;
	/* fill in last defaults */
	if (account->port == 0)
	{
	    if (account->tls && account->tls_nostarttls)
	    {
		se = getservbyname("pop3s", NULL);
		account->port = se ? ntohs(se->s_port) : 995;
	    }
	    else
	    {
		se = getservbyname("pop3", NULL);
		account->port = se ? ntohs(se->s_port) : 110;
	    }
	}
	if (!account->uidls_file)
	{
	    account->uidls_file = get_filename(homedir, UIDLSFILE);
	}
	/* check for consistency and completeness */
	if (check_account(account, &errstr) != CONF_EOK)
	{
	    if (account->id && account->conffile)
	    {
		print_error(_("account %s from %s: %s"), account->id, 
			account->conffile, mpop_sanitize_string(errstr));
	    }
	    else
	    {
		print_error("%s", mpop_sanitize_string(errstr));
	    }
	    error_code = EX_CONFIG;
	    goto exit;
	}
	if (retrmail && account->delivery_method == -1)
	{
	    if (account->id && account->conffile)
	    {
		print_error(_("account %s from %s: %s"),
			account->id, account->conffile,
			_("no delivery information"));
	    }
	    else
	    {
		print_error(_("no delivery information"));
	    }
	    error_code = EX_CONFIG;
	    goto exit;
	}
    }

    /* print configuration */
    if (print_conf)
    {
	lp = account_list;
	while (!list_is_empty(lp))
	{
	    lp = lp->next;
	    account = lp->data;
	    if (account->id && account->conffile)
	    {
		printf(_("using account %s from %s\n"), 
			account->id, account->conffile);
	    }
	    printf("host            = %s\n"
		    "port            = %d\n",
		    account->host,
		    account->port);
	    printf("timeout         = ");
	    if (account->timeout <= 0)
	    {
		printf(_("off\n"));
	    }
	    else
	    {
		if (account->timeout == 1)
		{
		    printf(_("1 second\n"));
		}
		else
		{
		    printf(_("%d seconds\n"), account->timeout);
		}
	    }
	    printf("pipelining      = %s\n"
		    "auth            = ",
		    account->pipelining ? _("on") : _("off"));
	    if (account->auth_mech[0] == '\0')
	    {
		printf(_("choose\n"));
	    }
	    else
	    {
		printf("%s\n", account->auth_mech);
	    }
	    printf("user            = %s\n"
		    "password        = %s\n"
		    "ntlmdomain      = %s\n"
		    "tls             = %s\n"
		    "tls_trust_file  = %s\n"
		    "tls_key_file    = %s\n"
		    "tls_cert_file   = %s\n"
		    "tls_starttls    = %s\n"
		    "tls_certcheck   = %s\n",
		    account->username ? account->username : _("(not set)"),
		    account->password ? "*" : _("(not set)"),
		    account->ntlmdomain ? account->ntlmdomain : _("(not set)"),
		    account->tls ? _("on") : _("off"), 
		    account->tls_trust_file ? 
		    	account->tls_trust_file : _("(not set)"),
		    account->tls_key_file ? 
		    	account->tls_key_file : _("(not set)"),
		    account->tls_cert_file ? 
		    	account->tls_cert_file : _("(not set)"),
		    account->tls_nostarttls ? _("off") : _("on"),
		    account->tls_nocertcheck ? _("off") : _("on"));
	    if (retrmail)
	    {
		printf("delivery        = ");
		if (account->delivery_method == DELIVERY_METHOD_MDA)
		{
		    printf("mda");
		}
		else if (account->delivery_method == DELIVERY_METHOD_MAILDIR)
		{
		    printf("maildir");
		}
		else if (account->delivery_method == DELIVERY_METHOD_MBOX)
		{
		    printf("mbox");
		}
		printf(" %s\n", account->delivery_args);
		printf("uidls file      = %s\n"
			"only_new        = %s\n"
			"keep            = %s\n", 
			account->uidls_file,
			account->only_new ? _("on") : _("off"),
			account->keep ? _("on") : _("off"));
		printf("killsize        = ");
		if (account->killsize < 0)
		{
		    printf(_("off\n"));
		}
		else
		{
		    printf("%ld\n", account->killsize);
		}
		printf("skipsize        = ");
		if (account->skipsize < 0)
		{
		    printf(_("off\n"));
		}
		else
		{
		    printf("%ld\n", account->skipsize);
		}
		printf("filter          = %s\n",
			account->filter ? account->filter : _("(not set)"));
	    }
	}
    }
    if (pretend || (!retrmail && !serverinfo))
    {
	error_code = EX_OK;
	goto exit;
    }
	
    /* initialize libraries */
    lp = account_list;
    while (!list_is_empty(lp))
    {
	lp = lp->next;
	account = lp->data;
	if (account->auth_mech && (strcmp(account->auth_mech, "") != 0)
		&& !pop3_client_supports_authmech(account->auth_mech))
	{
	    print_error(_("support for authentication method %s is not "
			"compiled in"), account->auth_mech);
	    error_code = EX_UNAVAILABLE;
	    goto exit;
	}
	if (account->tls)
	{
#ifdef HAVE_SSL
	    if (!tls_lib_initialized)
	    {
		if (tls_lib_init(&errstr) != TLS_EOK)
		{
		    print_error(_("cannot initialize TLS library: %s"), 
			    mpop_sanitize_string(errstr));
		    error_code = EX_SOFTWARE;
		    goto exit;
		}
		tls_lib_initialized = 1;
	    }
#else /* not HAVE_SSL */
	    print_error(_("support for TLS is not compiled in"));
	    error_code = EX_UNAVAILABLE;
	    goto exit;
#endif /* HAVE_SSL */
	}
    }
    if (net_lib_init(&errstr) != NET_EOK)
    {
	print_error(_("cannot initialize network library: %s"), 
		mpop_sanitize_string(errstr));
	error_code = EX_SOFTWARE;
	goto exit;
    }
    net_lib_initialized = 1;

    /* do the work */
    canonical_hostname = NULL;
    local_user = NULL;
    lp = account_list;
    while (!list_is_empty(lp))
    {
	lp = lp->next;
	account = lp->data;
	if (serverinfo)
	{
	    if ((error_code = mpop_serverinfo(account, debug, 
	    		    &errmsg, &errstr)) != EX_OK)
	    {
		if (errstr)
		{
		    print_error("%s", mpop_sanitize_string(errstr));
		    free(errstr);
		    errstr = NULL;
		}
		if (errmsg)
		{
	    	    print_error(_("POP3 server message: %s"), 
			    mpop_sanitize_string(errmsg));
		    free(errmsg);
		    errmsg = NULL;
		}		    
	    }
	}
	else /* retrmail */
	{
	    if (!canonical_hostname)
	    {
		canonical_hostname = net_get_canonical_hostname();
	    }
	    if (!local_user)
	    {
		local_user = get_username();
	    }
	    mpop_retrmail_abort = 0;
#ifdef HAVE_SIGACTION
    	    signal_handler.sa_handler = mpop_retrmail_signal_handler;
	    sigemptyset(&signal_handler.sa_mask);
    	    signal_handler.sa_flags = 0;
    	    (void)sigaction(SIGTERM, &signal_handler, &old_sigterm_handler);
	    (void)sigaction(SIGHUP, &signal_handler, &old_sighup_handler);
	    (void)sigaction(SIGINT, &signal_handler, &old_sigint_handler);
#endif /* HAVE_SIGACTION */
	    if ((error_code = mpop_retrmail(canonical_hostname, local_user,
			    account, debug, quiet, auth_only, status_only,
	    		    &errmsg, &errstr)) != EX_OK)
	    {
		if (errstr)
		{
		    print_error("%s", mpop_sanitize_string(errstr));
		    free(errstr);
		    errstr = NULL;
		}
		if (errmsg)
		{
	    	    print_error(_("POP3 server message: %s"), 
			    mpop_sanitize_string(errmsg));
		    free(errmsg);
		    errmsg = NULL;
		}		    
		if (account->id && account->conffile)
		{
		    print_error(_("error during mail retrieval "
				"(account %s from %s)"),
		    	    account->id, account->conffile);
		}
		else
		{
		    print_error(_("error during mail retrieval"));
		}
	    }
#ifdef HAVE_SIGACTION
    	    (void)sigaction(SIGTERM, &old_sigterm_handler, NULL);
	    (void)sigaction(SIGHUP, &old_sighup_handler, NULL);
	    (void)sigaction(SIGINT, &old_sigint_handler, NULL);
#endif /* HAVE_SIGACTION */    
	    if (mpop_retrmail_abort)
	    {
		break;
	    }
	}
    }
    free(canonical_hostname);
    free(local_user);
    
exit:
    /* clean up */
    free(errstr);
    free(errmsg);
    free(homedir);
#ifdef HAVE_SSL
    if (tls_lib_initialized)
    {
	tls_lib_deinit();
    }
#endif /* HAVE_SSL */
    if (net_lib_initialized)
    {
	net_lib_deinit();
    }
    free(conffile);
    if (conffile_account_list)
    {
	list_xfree(conffile_account_list, account_free);
    }
    if (account_list)
    {
	list_xfree(account_list, account_free);
    }
    account_free(cmdline_account);

    return error_code;
}
