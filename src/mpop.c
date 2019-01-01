/*
 * mpop.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2000, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014, 2015, 2016, 2018, 2019
 * Martin Lambers <marlam@marlam.de>
 * Dimitrios Apostolou <jimis@gmx.net> (UID handling)
 * Jay Soffian <jaysoffian@gmail.com> (Mac OS X keychain support)
 * Satoru SATOH <satoru.satoh@gmail.com> (GNOME keyring support)
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <getopt.h>
extern char *optarg;
extern int optind;
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#ifdef ENABLE_NLS
# include <locale.h>
#endif
#ifdef HAVE_LIBSECRET
# include <libsecret/secret.h>
#endif
#ifdef HAVE_MACOSXKEYRING
# include <Security/Security.h>
#endif

#include "gettext.h"
#define _(string) gettext(string)
#define N_(string) gettext_noop(string)

#include "xalloc.h"
#include "list.h"
#include "tools.h"
#include "conf.h"
#include "net.h"
#include "netrc.h"
#include "delivery.h"
#include "pop3.h"
#ifdef HAVE_TLS
#include "tls.h"
#endif /* HAVE_TLS */
#include "uidls.h"

#ifdef W32_NATIVE
# define PRINTFLLD "%I64d"
# define mkdir(path, mode) mkdir(path)
#else
# define PRINTFLLD "%lld"
#endif

/* Default file names. */
#ifdef W32_NATIVE
#define CONFFILE        "mpoprc.txt"
#define UIDLSFILE       "mpop_uidls\\%U_at_%H.txt"
#define USERNETRCFILE   "netrc.txt"
#define SYSNETRCFILE    "netrc.txt"
#else /* UNIX */
#define CONFFILE        ".mpoprc"
#define UIDLSFILE       ".mpop_uidls/%U_at_%H"
#define USERNETRCFILE   ".netrc"
#define SYSNETRCFILE    "netrc"
#endif


/* The name of this program */
const char *prgname;


/*
 * Die if memory allocation fails
 */

void xalloc_die(void)
{
    /* TRANSLATORS: mpop shares a lot of code and translatable strings with
       msmtp <https://marlam.de/msmtp>. */
    fprintf(stderr, _("%s: FATAL: %s\n"), prgname, strerror(ENOMEM));
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

        case NET_EPROXY:
            return EX_UNAVAILABLE;

        case NET_ELIBFAILED:
        default:
            return EX_SOFTWARE;
    }
}

#ifdef HAVE_TLS
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
#endif /* HAVE_TLS */

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
 * This function will be called by pop3_auth() to get a password if none was
 * given.
 * It tries to get it from the system's keychain (if available).
 * If that fails, it tries to read a password from .netrc.
 * If that fails, it tries to read a password from /dev/tty (not stdin) with
 * getpass().
 * It must return NULL on failure or a password in an allocated buffer.
 */

#ifdef HAVE_LIBSECRET
const SecretSchema *get_mpop_schema(void)
{
    static const SecretSchema schema = {
        "de.marlam.mpop.password", SECRET_SCHEMA_DONT_MATCH_NAME,
        {
            {  "host", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "service", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "user", SECRET_SCHEMA_ATTRIBUTE_STRING },
            {  "NULL", 0 },
        }
    };
    return &schema;
}
#endif

char *mpop_password_callback(const char *hostname, const char *user)
{
    char *netrc_directory;
    char *netrc_filename;
    netrc_entry *netrc_hostlist;
    netrc_entry *netrc_host;
#ifdef HAVE_MACOSXKEYRING
    void *password_data;
    UInt32 password_length;
    OSStatus status;
#endif
    char *prompt;
    char *gpw;
    char *password = NULL;

#ifdef HAVE_LIBSECRET
    if (!password)
    {
        gchar* libsecret_pw = secret_password_lookup_sync(
                get_mpop_schema(),
                NULL, NULL,
                "host", hostname,
                "service", "pop3",
                "user", user,
                NULL);
        if (!libsecret_pw)
        {
            /* for compatibility with passwords stored by the older
             * libgnome-keyring */
            libsecret_pw = secret_password_lookup_sync(
                    SECRET_SCHEMA_COMPAT_NETWORK,
                    NULL, NULL,
                    "user", user,
                    "protocol", "pop3",
                    "server", hostname,
                    NULL);
        }
        if (libsecret_pw)
        {
            password = xstrdup(libsecret_pw);
            secret_password_free(libsecret_pw);
        }
    }
#endif /* HAVE_LIBSECRET */

#ifdef HAVE_MACOSXKEYRING
    if (!password)
    {
        if (SecKeychainFindInternetPassword(
                    NULL,
                    strlen(hostname), hostname,
                    0, NULL,
                    strlen(user), user,
                    0, (char *)NULL,
                    0,
                    kSecProtocolTypePOP3,
                    kSecAuthenticationTypeDefault,
                    &password_length, &password_data,
                    NULL) == noErr)
        {
            password = xmalloc((password_length + 1) * sizeof(char));
            strncpy(password, password_data, (size_t)password_length);
            password[password_length] = '\0';
            SecKeychainItemFreeContent(NULL, password_data);
        }
    }
#endif /* HAVE_MACOSXKEYRING */

    if (!password)
    {
        netrc_directory = get_homedir();
        netrc_filename = get_filename(netrc_directory, USERNETRCFILE);
        free(netrc_directory);
        if ((netrc_hostlist = parse_netrc(netrc_filename)))
        {
            if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
            {
                password = xstrdup(netrc_host->password);
            }
            free_netrc(netrc_hostlist);
        }
        free(netrc_filename);
    }

    if (!password)
    {
        netrc_directory = get_sysconfdir();
        netrc_filename = get_filename(netrc_directory, SYSNETRCFILE);
        free(netrc_directory);
        if ((netrc_hostlist = parse_netrc(netrc_filename)))
        {
            if ((netrc_host = search_netrc(netrc_hostlist, hostname, user)))
            {
                password = xstrdup(netrc_host->password);
            }
            free_netrc(netrc_hostlist);
        }
        free(netrc_filename);
    }

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
 * mpop_print_tls_info()
 *
 * Prints information about a TLS session.
 */

#ifdef HAVE_TLS
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
#endif

void mpop_fingerprint_string(char *s, unsigned char *fingerprint, size_t len)
{
    const char *hex = "0123456789ABCDEF";
    size_t i;

    for (i = 0; i < len; i++)
    {
        s[3 * i + 0] = hex[(fingerprint[i] & 0xf0) >> 4];
        s[3 * i + 1] = hex[fingerprint[i] & 0x0f];
        s[3 * i + 2] = (i < len - 1 ? ':' : '\0');
    }
}

#ifdef HAVE_TLS
void mpop_print_tls_info(const char *tls_parameter_description, tls_cert_info_t *tci)
{
    const char *info_fieldname[6] = { N_("Common Name"), N_("Organization"),
        N_("Organizational unit"), N_("Locality"), N_("State or Province"),
        N_("Country") };
    char sha256_fingerprint_string[96];
    char sha1_fingerprint_string[60];
    char timebuf[128];          /* should be long enough for every locale */
    char *tmp;
    int i;

    printf(_("TLS session parameters:\n"));
    printf("    %s\n", tls_parameter_description
            ? tls_parameter_description : _("not available"));

    mpop_fingerprint_string(sha256_fingerprint_string,
            tci->sha256_fingerprint, 32);
    mpop_fingerprint_string(sha1_fingerprint_string,
            tci->sha1_fingerprint, 20);

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
    printf("        SHA256: %s\n", sha256_fingerprint_string);
    printf("        SHA1 (deprecated): %s\n", sha1_fingerprint_string);
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
 * If an error occurred, '*errstr' points to an allocated string that descibes
 * the error or is NULL, and '*errmsg' points to the offending messages from
 * the POP3 server or is NULL.
 */

int mpop_serverinfo(account_t *acc, int debug, char **errmsg, char **errstr)
{
    pop3_session_t *session;
    char server_greeting[POP3_BUFSIZE - 4];
#ifdef HAVE_TLS
    tls_cert_info_t *tci = NULL;
    char *tls_parameter_description = NULL;
#endif /* HAVE_TLS */
    const char *server_canonical_name;
    const char *server_address;
    int auth_successful;
    int e;


    /* Create a new pop3_server_t. We won't actually retrieve any mail, so the
     * FQDN and the local user are meaningless. */
    session = pop3_session_new(acc->pipelining, "", "", debug ? stdout : NULL);

    /* connect */
    if ((e = pop3_connect(session, acc->proxy_host, acc->proxy_port,
                    acc->host, acc->port, acc->source_ip, acc->timeout,
                    &server_canonical_name, &server_address, errstr))
            != NET_EOK)
    {
        pop3_session_free(session);
        e = exitcode_net(e);
        goto error_exit;
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        tci = tls_cert_info_new();
        if ((e = pop3_tls_init(session, acc->tls_key_file, acc->tls_cert_file,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha256_fingerprint,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_min_dh_prime_bits,
                        acc->tls_priorities, errstr)) != TLS_EOK)
        {
            pop3_session_free(session);
            e = exitcode_tls(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

    /* start tls for pop3s servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci,
                        &tls_parameter_description, errstr)) != TLS_EOK)
        {
            mpop_endsession(session, 0);
            e = exitcode_tls(e);
            goto error_exit;
        }
    }
#endif /* HAVE_TLS */

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
#ifdef HAVE_TLS
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
                        &tls_parameter_description, errstr)) != TLS_EOK)
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
#endif /* HAVE_TLS */

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
#ifdef HAVE_TLS
    if (acc->tls)
    {
        mpop_print_tls_info(tls_parameter_description, tci);
    }
#endif /* not HAVE_TLS */
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
#ifdef HAVE_TLS
    if ((acc->tls && !acc->tls_nostarttls)
            || (session->cap.flags & POP3_CAP_STLS))
#else
    if (session->cap.flags & POP3_CAP_STLS)
#endif /* not HAVE_TLS */
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
    if (session->cap.flags & POP3_CAP_AUTH_PLAIN)
    {
        printf("PLAIN ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_SCRAM_SHA_1)
    {
        printf("SCRAM-SHA-1 ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_EXTERNAL)
    {
        printf("EXTERNAL ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_GSSAPI)
    {
        printf("GSSAPI ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_APOP)
    {
        printf("APOP ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_CRAM_MD5)
    {
        printf("CRAM-MD5 ");
    }
    if (session->cap.flags & POP3_CAP_AUTH_DIGEST_MD5)
    {
        printf("DIGEST-MD5 ");
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
#ifdef HAVE_TLS
    if ((session->cap.flags & POP3_CAP_STLS) && !acc->tls)
#else
    if (session->cap.flags & POP3_CAP_STLS)
#endif /* not HAVE_TLS */
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
#ifdef HAVE_TLS
    if (tci)
    {
        tls_cert_info_free(tci);
        free(tls_parameter_description);
    }
#endif /* HAVE_TLS */
    return e;
}


/*
 * mpop_hr_size()
 *
 * Prints the size argument in human readable form into an allocated string.
 * Returns a pointer to this string.
 */

char *mpop_hr_size(long long size)
{
    char *s;

    if (size >= 1024 * 1024 * 1024)
    {
        s = xasprintf(_("%.2f GiB"), (float)size / (float)(1024 * 1024 * 1024));
    }
    else if (size >= 1024 * 1024)
    {
        s = xasprintf(_("%.2f MiB"), (float)size / (float)(1024 * 1024));
    }
    else if (size >= 1024)
    {
        s = xasprintf(_("%.2f KiB"), (float)size / 1024.0f);
    }
    else if (size > 1 || size == 0)
    {
        s = xasprintf(_(PRINTFLLD " bytes"), size);
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

void mpop_retr_progress_start(long i, long number, long long size)
{
    if (size > 0)
    {
        char *sizestr = mpop_hr_size(size);
        printf(_("retrieving message %ld of %ld (%s): "), i, number, sizestr);
        free(sizestr);
    }
    else
    {
        printf(_("retrieving message %ld of %ld: "), i, number);
    }
    printf("  0%%\b\b\b\b");
    fflush(stdout);
}

void mpop_retr_progress(long i, long number,
        long long rcvd, long long size, int percent)
{
    (void)i;
    (void)number;
    (void)rcvd;
    (void)size;

    printf("%3d\b\b\b", percent);
    fflush(stdout);
}

void mpop_retr_progress_end(long i, long number, long long size)
{
    (void)i;
    (void)number;
    (void)size;

    printf("100\n");
}

void mpop_retr_progress_abort(long i, long number, long long size)
{
    (void)i;
    (void)number;
    (void)size;

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

volatile sig_atomic_t mpop_retrmail_abort = 0;
void mpop_retrmail_signal_handler(int signum)
{
    (void)signum;

    mpop_retrmail_abort = 1;
}

int mpop_retrmail(const char *canonical_hostname, const char *local_user,
        account_t *acc, int debug,
        int print_status, int print_progress, int auth_only, int status_only,
        char **errmsg, char **errstr)
{
    pop3_session_t *session;
#ifdef HAVE_TLS
    tls_cert_info_t *tci = NULL;
    char *tls_parameter_description = NULL;
#endif /* HAVE_TLS */
    int e;
    long i, j;
    /* for identifying new messages: */
    FILE *uidls_fileptr;
    list_t *uidl_list;
    uidl_t *uidl;
    /* for status output: */
    char *sizestr;
    /* For errors that happen after a message is retrieved and delivered, and
     * thus after we can abort the POP3 session without caring about double
     * deliveries: */
    int late_error;
    char *late_errmsg;
    char *late_errstr;
    /* Whether QUIT was sent: */
    int quit_was_sent = 0;


    /* create a new pop3_server_t */
    session = pop3_session_new(acc->pipelining, canonical_hostname, local_user,
            debug ? stdout : NULL);

    /* connect */
    if ((e = pop3_connect(session, acc->proxy_host, acc->proxy_port,
                    acc->host, acc->port, acc->source_ip, acc->timeout,
                    NULL, NULL, errstr)) != NET_EOK)
    {
        pop3_session_free(session);
        return exitcode_net(e);
    }

    /* prepare tls */
#ifdef HAVE_TLS
    if (acc->tls)
    {
        if ((e = pop3_tls_init(session, acc->tls_key_file, acc->tls_cert_file,
                        acc->tls_trust_file, acc->tls_crl_file,
                        acc->tls_sha256_fingerprint,
                        acc->tls_sha1_fingerprint, acc->tls_md5_fingerprint,
                        acc->tls_min_dh_prime_bits,
                        acc->tls_priorities, errstr)) != TLS_EOK)
        {
            pop3_session_free(session);
            return exitcode_tls(e);
        }
    }
#endif /* HAVE_TLS */

    /* start tls for pop3s servers */
#ifdef HAVE_TLS
    if (acc->tls && acc->tls_nostarttls)
    {
        if (debug)
        {
            tci = tls_cert_info_new();
        }
        if ((e = pop3_tls(session, acc->host, acc->tls_nocertcheck, tci,
                        &tls_parameter_description, errstr)) != POP3_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
                free(tls_parameter_description);
            }
            mpop_endsession(session, 0);
            return exitcode_tls(e);
        }
        if (debug)
        {
            mpop_print_tls_info(tls_parameter_description, tci);
            tls_cert_info_free(tci);
            free(tls_parameter_description);
        }
    }
#endif /* HAVE_TLS */

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
#ifdef HAVE_TLS
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
                        &tls_parameter_description, errstr)) != TLS_EOK)
        {
            if (debug)
            {
                tls_cert_info_free(tci);
                free(tls_parameter_description);
            }
            mpop_endsession(session, 0);
            return exitcode_tls(e);
        }
        if (debug)
        {
            mpop_print_tls_info(tls_parameter_description, tci);
            tls_cert_info_free(tci);
            free(tls_parameter_description);
        }
        /* get capabilities again */
        if ((session->cap.flags & POP3_CAP_CAPA)
                && (e = pop3_capa(session, errstr)) != POP3_EOK)
        {
            mpop_endsession(session, 0);
            return exitcode_pop3(e);
        }
    }
#endif /* HAVE_TLS */

    if (mpop_retrmail_abort)
    {
        mpop_endsession(session, 0);
        *errstr = xasprintf(_("operation aborted"));
        return EX_TEMPFAIL;
    }

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
     * AUTHENTICATION and TRANSACTION state (see RFC 2449).
     * However, as of 2005-01-17, at least pop.gmail.com violates this part of
     * the RFC by announcing the PIPELINING, UIDL, and TOP capabilities only
     * after authentication. (Update 2007-03-19: now UIDL is announced before
     * authentication, but TOP and PIPELINING still are not).
     * This general workaround issues CAPA again if it is supported and
     * - filtering is used and the TOP capability was not seen or
     * - pipelining is to be set automatically and the PIPELINING capability
     *   was not seen or
     * - the UIDL capability was not seen.
     * Other capabilities won't be used, so we do not care about them.
     */
    if ((session->cap.flags & POP3_CAP_CAPA)
            && ((acc->filter
                    && !(session->cap.flags & POP3_CAP_TOP))
                || (acc->pipelining == 2
                    && !(session->cap.flags & POP3_CAP_PIPELINING))
                || !(session->cap.flags & POP3_CAP_UIDL)))
    {
        if (acc->pipelining == 2)
        {
            session->pipelining = 2;
        }
        if ((e = pop3_capa(session, errstr)) != POP3_EOK)
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

    /* get status and scan listing */
    if ((e = pop3_stat(session, errmsg, errstr)) != POP3_EOK)
    {
        mpop_endsession(session, 0);
        return exitcode_pop3(e);
    }
    if (session->total_number > 0)
    {
        if ((e = pop3_list(session, &mpop_retrmail_abort, errmsg, errstr))
                != POP3_EOK)
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

    /* Load the list of UID lists (if the file does not exist, the returned
     * list will be empty) */
    if ((e = uidls_read(acc->uidls_file, &uidls_fileptr, &uidl_list, errstr))
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

    /* retrieve the UIDs */
    if (session->total_number > 0)
    {
        if ((session->cap.flags & POP3_CAP_CAPA)
                && !(session->cap.flags & POP3_CAP_UIDL))
        {
            /* the POP3 server does not support UIDL */
        }
        else if ((e = pop3_uidl(session, uidl->uidv, uidl->n, acc->only_new,
                        &mpop_retrmail_abort, errmsg, errstr)) != POP3_EOK)
        {
            if (e != POP3_EUNAVAIL)
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

    /* Print status */
    if (print_status)
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
            if (session->new_number > 0 && session->new_size > 0)
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
        if (session->total_number > 0 && session->total_size > 0)
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
        fclose(uidls_fileptr);
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
                if (!(session->is_old[i - 1]))
                {
                    session->is_old[i - 1] = 1;
                    session->old_number++;
                }
                if (print_progress)
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
                if (print_progress)
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
        fclose(uidls_fileptr);
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
            fclose(uidls_fileptr);
            mpop_endsession(session, 1);
            return EX_UNAVAILABLE;
        }
        if ((e = pop3_filter(session, &mpop_retrmail_abort, acc->filter,
                        print_progress ? mpop_filter_output : NULL, acc,
                        errmsg, errstr)) != POP3_EOK)
        {
            if (uidl_list)
            {
                list_xfree(uidl_list, uidl_free);
            }
            fclose(uidls_fileptr);
            mpop_endsession(session, 0);
            return exitcode_pop3(e);
        }
    }

    /* Once pop3_retr() is called, we cannot just abort the session and forget
     * everything we've done so far, because that would mean double mail
     * deliveries. Instead, we at least have to update the UIDLs file. */
    late_error = POP3_EOK;
    late_errmsg = NULL;
    late_errstr = NULL;

    /* Retrieve mails and update the UIDL accordingly */
    if (session->total_number > 0)
    {
        late_error = pop3_retr(session, &mpop_retrmail_abort,
                acc->delivery_method, acc->delivery_args, acc->received_header,
                print_progress ? mpop_retr_progress_start : NULL,
                print_progress ? mpop_retr_progress : NULL,
                print_progress ? mpop_retr_progress_end : NULL,
                print_progress ? mpop_retr_progress_abort : NULL,
                &late_errmsg, &late_errstr);
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
    }

    /* Delete mails. If a failure occurs, save the current UIDL state.
     * Otherwise, end the session to commit the changes, then
     * update the UIDL state and save it. */
    if (late_error == POP3_EOK && !acc->keep)
    {
        if ((e = pop3_dele(session, &mpop_retrmail_abort, errmsg, errstr))
                != POP3_EOK)
        {
            (void)uidls_write(acc->uidls_file, uidls_fileptr, uidl_list, NULL);
            list_xfree(uidl_list, uidl_free);
            mpop_endsession(session, 0);
            return exitcode_uidls(e);
        }
        if ((e = pop3_quit(session, errmsg, errstr)) != POP3_EOK)
        {
            (void)uidls_write(acc->uidls_file, uidls_fileptr, uidl_list, NULL);
            list_xfree(uidl_list, uidl_free);
            mpop_endsession(session, 0);
            return exitcode_uidls(e);
        }
        quit_was_sent = 1;
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
    }
    if ((e = uidls_write(acc->uidls_file, uidls_fileptr, uidl_list, errstr))
            != UIDLS_EOK)
    {
        list_xfree(uidl_list, uidl_free);
        mpop_endsession(session, 0);
        return exitcode_uidls(e);
    }
    list_xfree(uidl_list, uidl_free);
    mpop_endsession(session, late_error == POP3_EOK && !quit_was_sent);

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
 * mpop_split_address()
 *
 * Splits a mail address into a local part (before the last '@') and a domain
 * part (after the last '@').
 */

void mpop_split_address(const char *address, char **local_part, char **domain_part)
{
    const char *p = strrchr(address, '@');
    if (p)
    {
        size_t local_part_len = p - address;
        size_t domain_part_len = strlen(p + 1);
        *local_part = xmalloc(local_part_len + 1);
        strncpy(*local_part, address, local_part_len);
        (*local_part)[local_part_len] = '\0';
        *domain_part = xmalloc(domain_part_len + 1);
        strcpy(*domain_part, p + 1);
    }
    else
    {
        size_t local_part_len = strlen(address);
        *local_part = xmalloc(local_part_len + 1);
        strcpy(*local_part, address);
        *domain_part = NULL;
    }
}


/*
 * mpop_hostname_matches_domain()
 *
 * Checks whether the given host name is within the given domain.
 */

int mpop_hostname_matches_domain(const char *hostname, const char *domain)
{
    size_t hostname_len = strlen(hostname);
    size_t domain_len = strlen(domain);
    size_t i;

    if (hostname_len < domain_len || domain_len < 1)
        return 0;

    for (i = 0; i < domain_len; i++)
    {
        if (tolower(domain[domain_len - 1 - i])
                != tolower(hostname[hostname_len - 1 - i]))
        {
            return 0;
        }
    }
    return 1;
}


/*
 * mpop_configure()
 *
 * Tries autoconfiguration for the given mail address based on the methods
 * described in RFC 8314 (SRV records).
 * If successfull, this function will print a configuration file excerpt to
 * standard output and return EX_OK.
 * Otherwise, it will print an appropriate error message to standard error
 * and return an EX_* status.
 */

int mpop_configure(const char *address, const char *conffile)
{
#ifdef HAVE_LIBRESOLV

    int e;

    char *local_part;
    char *domain_part;

    char *pop3s_query;
    char *pop3_query;

    char *hostname = NULL;
    int port = -1;
    int starttls = -1;

    char *tmpstr;

    mpop_split_address(address, &local_part, &domain_part);
    if (!domain_part)
    {
        print_error(_("automatic configuration based on SRV records failed: %s"),
                _("address has no domain part"));
        free(local_part);
        return EX_DATAERR;
    }

    pop3s_query = net_get_srv_query(domain_part, "pop3s");
    e = net_get_srv_record(pop3s_query, &hostname, &port);
    if (e == NET_EOK) {
        starttls = 0;
    } else {
        pop3_query = net_get_srv_query(domain_part, "pop3");
        e = net_get_srv_record(pop3_query, &hostname, &port);
        if (e == NET_EOK) {
            starttls = 1;
        } else {
            char *errstr = xasprintf(_("no SRV records for %s or %s"),
                    pop3s_query, pop3_query);
            print_error(_("automatic configuration based on SRV records failed: %s"),
                    errstr);
            free(errstr);
            free(pop3s_query);
            free(pop3_query);
            free(local_part);
            free(domain_part);
            return EX_NOHOST;
        }
        free(pop3_query);
    }
    free(pop3s_query);

    /* comment header */

    tmpstr = xasprintf(_("copy this to your configuration file %s"), conffile);
    printf("# - %s\n", tmpstr);
    free(tmpstr);
    if (!mpop_hostname_matches_domain(hostname, domain_part))
        printf("# - %s\n", _("warning: the host does not match the mail domain; please check"));
#if defined HAVE_LIBSECRET
    tmpstr = xasprintf("secret-tool store --label=mpop host %s service pop3 user %s", hostname, local_part);
    printf("# - %s\n#   %s\n", _("add your password to the key ring:"), tmpstr);
    free(tmpstr);
#elif defined HAVE_MACOSXKEYRING
    tmpstr = xasprintf("security add-internet-password -s %s -r pop3 -a %s -w", hostname, local_part);
    printf("# - %s\n#   %s\n", _("add your password to the key ring:"), tmpstr);
    free(tmpstr);
#else
    printf("# - %s\n#   %s\n", _("encrypt your password:"), "gpg -e -o ~/.mpop-password.gpg");
#endif
    printf("# - %s\n", _("adjust the delivery command"));

    /* account definition */
    printf("account %s\n", address);
    printf("host %s\n", hostname);
    printf("port %d\n", port);
    printf("tls on\n");
    printf("tls_starttls %s\n", starttls ? "on" : "off");
    printf("user %s\n", local_part);
#if !defined HAVE_LIBSECRET && !defined HAVE_MACOSXKEYRING
    printf("passwordeval gpg --no-tty -q -d ~/.mpop-password.gpg\n");
#endif
    printf("delivery mbox ~/MAIL\n");

    free(local_part);
    free(domain_part);
    free(hostname);
    return EX_OK;

#else

    print_error(_("automatic configuration based on SRV records failed: %s"),
            _("this system lacks libresolv"));
    return EX_UNAVAILABLE;

#endif
}


/*
 * Construct a list of accounts from a list of account ids.
 * If there are no account ids (accountidc == 0), use the account "default".
 * If accountidc is -1, then all accounts will be used.
 * account_list will be created, regardless of success or failure.
 * An error message will be printed in case of failure.
 * Used error codes: 1 = Account not found
 */

int get_account_list(const char *conffile, list_t *conffile_account_list,
        int accountidc, char **accountidv, list_t **account_list)
{
    account_t *a;
    list_t *lp, *lp2;
    int i;

    *account_list = list_new();
    lp = *account_list;
    if (accountidc == -1)
    {
        if (list_is_empty(conffile_account_list))
        {
            print_error(_("%s: no accounts defined"), conffile);
            return 1;
        }
        else
        {
            lp2 = conffile_account_list;
            while (!list_is_empty(lp2))
            {
                lp2 = lp2->next;
                list_insert(lp, account_copy(lp2->data));
                lp = lp->next;
            }
        }
    }
    else if (accountidc == 0)
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
 * Takes a pathname as an argument, and checks that all the directories in the
 * pathname exist. Otherwise, they are created. Returns 0 if the directory
 * component of 'pathname' exists when done, and 1 otherwise. In this case,
 * errno will be set.
 */

int make_needed_dirs(const char *pathname)
{
    struct stat statbuf;
    int statret;
    int error;
    const char *dir_part_end;
    char *dir_part;

    if (pathname[0] == '\0')
    {
        return 0;
    }

    error = 0;
    dir_part_end = strchr(pathname + 1, PATH_SEP);
#if W32_NATIVE
    if (dir_part_end - pathname == 2
            && ((pathname[0] >= 'a' && pathname[0] <= 'z')
                || (pathname[0] >= 'A' && pathname[0] <= 'Z'))
            && pathname[1] == ':')
    {
        /* skip drive letter ("C:\" and similar) */
        dir_part_end = strchr(dir_part_end + 1, PATH_SEP);
    }
    else if (dir_part_end - pathname == 1)
    {
        /* skip network resource name ("\\server\" and similar) */
        dir_part_end = strchr(dir_part_end + 1, PATH_SEP);
        if (dir_part_end)
        {
            dir_part_end = strchr(dir_part_end + 1, PATH_SEP);
        }
    }
#endif
    while (dir_part_end && !error)
    {
        dir_part = xstrndup(pathname, dir_part_end - pathname);
        statret = stat(dir_part, &statbuf);
        if (statret == 0 && !S_ISDIR(statbuf.st_mode))
        {
            /* "'dir_part' exists but is not a directory" */
            errno = ENOTDIR;
            error = 1;
        }
        else if (statret != 0 && errno != ENOENT)
        {
            /* "cannot stat 'dir_part'" */
            /* errno was set by stat() */
            error = 1;
        }
        else if (statret != 0)  /* errno is ENOENT */
        {
            if (mkdir(dir_part, 0700) != 0)
            {
                /* "cannot create 'dir_part'" */
                /* errno was set by mkdir() */
                error = 1;
            }
        }
        free(dir_part);
        dir_part_end = strchr(dir_part_end + 1, PATH_SEP);
    }

    return error;
}


/*
 * The main function.
 * It returns values from sysexits.h (like sendmail does).
 */

/* long options without a corresponding short option */
#define LONGONLYOPT_VERSION                     0
#define LONGONLYOPT_HELP                        1
#define LONGONLYOPT_HOST                        2
#define LONGONLYOPT_PORT                        3
#define LONGONLYOPT_TIMEOUT                     4
#define LONGONLYOPT_PIPELINING                  5
#define LONGONLYOPT_RECEIVED_HEADER             6
#define LONGONLYOPT_AUTH                        7
#define LONGONLYOPT_USER                        8
#define LONGONLYOPT_PASSWORDEVAL                9
#define LONGONLYOPT_TLS                         10
#define LONGONLYOPT_TLS_STARTTLS                11
#define LONGONLYOPT_TLS_TRUST_FILE              12
#define LONGONLYOPT_TLS_CRL_FILE                13
#define LONGONLYOPT_TLS_FINGERPRINT             14
#define LONGONLYOPT_TLS_KEY_FILE                15
#define LONGONLYOPT_TLS_CERT_FILE               16
#define LONGONLYOPT_TLS_CERTCHECK               17
#define LONGONLYOPT_TLS_FORCE_SSLV3             18
#define LONGONLYOPT_TLS_MIN_DH_PRIME_BITS       19
#define LONGONLYOPT_TLS_PRIORITIES              20
#define LONGONLYOPT_KILLSIZE                    21
#define LONGONLYOPT_SKIPSIZE                    22
#define LONGONLYOPT_FILTER                      23
#define LONGONLYOPT_DELIVERY                    24
#define LONGONLYOPT_UIDLS_FILE                  25
#define LONGONLYOPT_PROXY_HOST                  26
#define LONGONLYOPT_PROXY_PORT                  27
#define LONGONLYOPT_SOURCE_IP                   28
#define LONGONLYOPT_CONFIGURE                   29

int main(int argc, char *argv[])
{
    /* the configuration */
    int print_version;
    int print_help;
    int print_conf;
    int debug;
    int pretend;
    int print_status;
    int print_progress;
    /* mode of operation */
    int retrmail;
    int serverinfo;
    int configure;
    int all_accounts;
    int auth_only;
    int status_only;
    /* mail address for --configure */
    char *configure_address = NULL;
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
#if HAVE_SIGACTION
    struct sigaction signal_handler;
    struct sigaction old_sigterm_handler;
    struct sigaction old_sighup_handler;
    struct sigaction old_sigint_handler;
#elif HAVE_SIGNAL
    void (*old_sigterm_handler)(int);
    void (*old_sighup_handler)(int);
    void (*old_sigint_handler)(int);
#endif
    /* misc */
#if HAVE_GETSERVBYNAME
    struct servent *se;
#endif
    int c;
    int net_lib_initialized = 0;
#ifdef HAVE_TLS
    int tls_lib_initialized = 0;
#endif /* HAVE_TLS */
    /* option handling */
    struct option options[] =
    {
        { "version",               no_argument,       0, LONGONLYOPT_VERSION },
        { "help",                  no_argument,       0, LONGONLYOPT_HELP },
        { "configure",             required_argument, 0, LONGONLYOPT_CONFIGURE },
        { "quiet",                 no_argument,       0, 'q' },
        { "half-quiet",            no_argument,       0, 'Q' },
        { "pretend",               no_argument,       0, 'P' },
        { "debug",                 no_argument,       0, 'd' },
        { "serverinfo",            no_argument,       0, 'S' },
        { "file",                  required_argument, 0, 'C' },
        { "auth-only",             no_argument,       0, 'A' },
        { "all-accounts",          no_argument,       0, 'a' },
        { "status-only",           no_argument,       0, 's' },
        { "delivery",              required_argument, 0, LONGONLYOPT_DELIVERY },
        { "uidls-file",            required_argument, 0,
            LONGONLYOPT_UIDLS_FILE },
        { "only-new",              optional_argument, 0, 'n' },
        { "keep",                  optional_argument, 0, 'k' },
        { "killsize",              required_argument, 0, LONGONLYOPT_KILLSIZE },
        { "skipsize",              required_argument, 0, LONGONLYOPT_SKIPSIZE },
        { "filter",                required_argument, 0, LONGONLYOPT_FILTER },
        { "host",                  required_argument, 0, LONGONLYOPT_HOST },
        { "port",                  required_argument, 0, LONGONLYOPT_PORT },
        { "timeout",               required_argument, 0, LONGONLYOPT_TIMEOUT},
        { "pipelining",            required_argument, 0,
            LONGONLYOPT_PIPELINING },
        { "received-header",       optional_argument, 0,
            LONGONLYOPT_RECEIVED_HEADER },
        { "auth",                  optional_argument, 0, LONGONLYOPT_AUTH },
        { "user",                  required_argument, 0, LONGONLYOPT_USER },
        { "passwordeval",          required_argument, 0,
            LONGONLYOPT_PASSWORDEVAL },
        { "proxy-host",            required_argument, 0, LONGONLYOPT_PROXY_HOST },
        { "proxy-port",            required_argument, 0, LONGONLYOPT_PROXY_PORT },
        { "source-ip",             required_argument, 0, LONGONLYOPT_SOURCE_IP },
        { "tls",                   optional_argument, 0, LONGONLYOPT_TLS },
        { "tls-starttls",          optional_argument, 0,
            LONGONLYOPT_TLS_STARTTLS },
        { "tls-trust-file",        required_argument, 0,
            LONGONLYOPT_TLS_TRUST_FILE },
        { "tls-crl-file",          required_argument, 0,
            LONGONLYOPT_TLS_CRL_FILE },
        { "tls-fingerprint",       required_argument, 0,
            LONGONLYOPT_TLS_FINGERPRINT },
        { "tls-key-file",          required_argument, 0,
            LONGONLYOPT_TLS_KEY_FILE },
        { "tls-cert-file",         required_argument, 0,
            LONGONLYOPT_TLS_CERT_FILE },
        { "tls-certcheck",         optional_argument, 0,
            LONGONLYOPT_TLS_CERTCHECK },
        { "tls-force-sslv3",       optional_argument, 0,
            LONGONLYOPT_TLS_FORCE_SSLV3 },
        { "tls-min-dh-prime-bits", required_argument, 0,
            LONGONLYOPT_TLS_MIN_DH_PRIME_BITS },
        { "tls-priorities",        required_argument, 0,
            LONGONLYOPT_TLS_PRIORITIES },
        { 0, 0, 0, 0 }
    };

    /* Avoid the side effects of text mode interpretations on DOS systems. */
#if defined W32_NATIVE
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
    print_status = 1;
    print_progress = 1;
    retrmail = 1;
    serverinfo = 0;
    configure = 0;
    all_accounts = 0;
    auth_only = 0;
    status_only = 0;
    cmdline_account = account_new(NULL, NULL);
    for (;;)
    {
        c = getopt_long(argc, argv, "qQPdSC:aAsn::k::", options, NULL);
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
                configure = 0;
                break;

            case LONGONLYOPT_HELP:
                print_help = 1;
                retrmail = 0;
                serverinfo = 0;
                configure = 0;
                break;

            case LONGONLYOPT_CONFIGURE:
                configure = 1;
                retrmail = 0;
                serverinfo = 0;
                free(configure_address);
                configure_address = xstrdup(optarg);
                break;

            case 'q':
                print_status = 0;
                print_progress = 0;
                break;

            case 'Q':
                print_progress = 0;
                break;

            case 'P':
                print_conf = 1;
                pretend = 1;
                break;

            case 'd':
                print_conf = 1;
                debug = 1;
                /* progress output would interfere with debugging output */
                print_progress = 0;
                break;

            case 'S':
                serverinfo = 1;
                retrmail = 0;
                break;

            case 'a':
                all_accounts = 1;
                break;

            case 'A':
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
                else if (strcmp(optarg, "auto") == 0)
                {
                    cmdline_account->pipelining = 2;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--pipelining");
                    error_code = 1;
                }
                cmdline_account->mask |= ACC_PIPELINING;
                break;

            case LONGONLYOPT_RECEIVED_HEADER:
                if (!optarg || is_on(optarg))
                {
                    cmdline_account->received_header = 1;
                }
                else if (is_off(optarg))
                {
                    cmdline_account->received_header = 0;
                }
                else
                {
                    print_error(_("invalid argument %s for %s"),
                            optarg, "--received-header");
                    error_code = 1;
                }
                cmdline_account->mask |= ACC_RECEIVED_HEADER;
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

            case LONGONLYOPT_PASSWORDEVAL:
                free(cmdline_account->passwordeval);
                cmdline_account->passwordeval =
                    (*optarg == '\0') ? NULL : xstrdup(optarg);
                cmdline_account->mask |= ACC_PASSWORDEVAL;
                break;

            case LONGONLYOPT_PROXY_HOST:
                free(cmdline_account->proxy_host);
                if (*optarg)
                {
                    cmdline_account->proxy_host = xstrdup(optarg);
                }
                else
                {
                    cmdline_account->proxy_host = NULL;
                }
                cmdline_account->mask |= ACC_PROXY_HOST;
                break;

            case LONGONLYOPT_PROXY_PORT:
                if (*optarg)
                {
                    cmdline_account->proxy_port = get_non_neg_int(optarg);
                    if (cmdline_account->proxy_port < 1
                            || cmdline_account->proxy_port > 65535)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--proxy-port");
                        error_code = 1;
                    }
                }
                else
                {
                    cmdline_account->proxy_port = 0;
                }
                cmdline_account->mask |= ACC_PROXY_PORT;
                break;

            case LONGONLYOPT_SOURCE_IP:
                free(cmdline_account->source_ip);
                if (*optarg)
                {
                    cmdline_account->source_ip = xstrdup(optarg);
                }
                else
                {
                    cmdline_account->source_ip = NULL;
                }
                cmdline_account->mask |= ACC_SOURCE_IP;
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

            case LONGONLYOPT_TLS_TRUST_FILE:
                free(cmdline_account->tls_trust_file);
                cmdline_account->tls_trust_file = (*optarg == '\0')
                    ? NULL : expand_tilde(optarg);
                cmdline_account->mask |= ACC_TLS_TRUST_FILE;
                break;

            case LONGONLYOPT_TLS_CRL_FILE:
                free(cmdline_account->tls_crl_file);
                cmdline_account->tls_crl_file = (*optarg == '\0')
                    ? NULL : expand_tilde(optarg);
                cmdline_account->mask |= ACC_TLS_CRL_FILE;
                break;

            case LONGONLYOPT_TLS_FINGERPRINT:
                free(cmdline_account->tls_sha256_fingerprint);
                cmdline_account->tls_sha256_fingerprint = NULL;
                free(cmdline_account->tls_sha1_fingerprint);
                cmdline_account->tls_sha1_fingerprint = NULL;
                free(cmdline_account->tls_md5_fingerprint);
                cmdline_account->tls_md5_fingerprint = NULL;
                if (*optarg)
                {
                    if (strlen(optarg) == 2 * 32 + 31)
                    {
                        cmdline_account->tls_sha256_fingerprint =
                            get_fingerprint(optarg, 32);
                    }
                    else if (strlen(optarg) == 2 * 20 + 19)
                    {
                        cmdline_account->tls_sha1_fingerprint =
                            get_fingerprint(optarg, 20);
                    }
                    else if (strlen(optarg) == 2 * 16 + 15)
                    {
                        cmdline_account->tls_md5_fingerprint =
                            get_fingerprint(optarg, 16);
                    }
                    if (!cmdline_account->tls_sha256_fingerprint
                            && !cmdline_account->tls_sha1_fingerprint
                            && !cmdline_account->tls_md5_fingerprint)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--tls-fingerprint");
                        error_code = 1;
                    }
                }
                cmdline_account->mask |= ACC_TLS_FINGERPRINT;
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

            case LONGONLYOPT_TLS_FORCE_SSLV3:
                /* silently ignored for compatibility with versions <= 1.0.29 */
                break;

            case LONGONLYOPT_TLS_MIN_DH_PRIME_BITS:
                if (*optarg == '\0')
                {
                    cmdline_account->tls_min_dh_prime_bits = -1;
                }
                else
                {
                    cmdline_account->tls_min_dh_prime_bits =
                        get_non_neg_int(optarg);
                    if (cmdline_account->tls_min_dh_prime_bits < 1)
                    {
                        print_error(_("invalid argument %s for %s"),
                                optarg, "--tls-min-dh-prime-bits");
                        error_code = 1;
                    }
                }
                cmdline_account->mask |= ACC_TLS_MIN_DH_PRIME_BITS;
                break;

            case LONGONLYOPT_TLS_PRIORITIES:
                free(cmdline_account->tls_priorities);
                if (*optarg)
                {
                    cmdline_account->tls_priorities = xstrdup(optarg);
                }
                else
                {
                    cmdline_account->tls_priorities = NULL;
                }
                cmdline_account->mask |= ACC_TLS_PRIORITIES;
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
                else if (strncmp(optarg, "exchange,", 9) == 0)
                {
                    cmdline_account->delivery_method = DELIVERY_METHOD_EXCHANGE;
                    free(cmdline_account->delivery_args);
                    cmdline_account->delivery_args = expand_tilde(optarg + 9);
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
        printf(_("Platform: %s\n"), PLATFORM);
        /* TLS/SSL support */
        printf(_("TLS/SSL library: %s\n"),
#ifdef HAVE_LIBGNUTLS
                "GnuTLS"
#elif defined (HAVE_LIBSSL)
                "OpenSSL"
#else
                _("none")
#endif
              );
        /* Authentication support */
        printf(_("Authentication library: %s\n"
                    "Supported authentication methods:\n"),
#ifdef HAVE_LIBGSASL
                _("GNU SASL; user and apop: built-in")
#else
                _("built-in")
#endif /* HAVE_LIBGSASL */
              );
        if (pop3_client_supports_authmech("USER"))
        {
            printf("user ");
        }
        if (pop3_client_supports_authmech("PLAIN"))
        {
            printf("plain ");
        }
        if (pop3_client_supports_authmech("SCRAM-SHA-1"))
        {
            printf("scram-sha-1 ");
        }
        if (pop3_client_supports_authmech("EXTERNAL"))
        {
            printf("external ");
        }
        if (pop3_client_supports_authmech("GSSAPI"))
        {
            printf("gssapi ");
        }
        if (pop3_client_supports_authmech("APOP"))
        {
            printf("apop ");
        }
        if (pop3_client_supports_authmech("CRAM-MD5"))
        {
            printf("cram-md5 ");
        }
        if (pop3_client_supports_authmech("DIGEST-MD5"))
        {
            printf("digest-md5 ");
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
#if defined(HAVE_LIBIDN) \
        || (defined(HAVE_GAI_IDN) && (!defined(HAVE_TLS) \
            || (defined(HAVE_LIBGNUTLS) && GNUTLS_VERSION_NUMBER >= 0x030400)))
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
        printf("\n");
        printf(_("Keyring support: "));
#if !defined HAVE_LIBSECRET && !defined HAVE_MACOSXKEYRING
        printf(_("none"));
#else
# ifdef HAVE_LIBSECRET
        printf(_("Gnome "));
# endif
# ifdef HAVE_MACOSXKEYRING
        printf(_("MacOS "));
# endif
#endif
        printf("\n");
        {
            char *conffile = get_userconfig(CONFFILE);
            printf(_("Configuration file name: %s\n"), conffile);
            free(conffile);
        }
        printf("\n");
        printf(_("Copyright (C) 2018 Martin Lambers and others.\n"
                    "This is free software.  You may redistribute copies of "
                        "it under the terms of\n"
                    "the GNU General Public License "
                        "<http://www.gnu.org/licenses/gpl.html>.\n"
                    "There is NO WARRANTY, to the extent permitted by law.\n"));
    }
    if (print_help)
    {
        printf(_("Usage:\n\n"));
        printf(_("Mail retrieval mode (default):\n"
                    "  %s [option...] [--] account...\n"
                    "  %s --host=host [option...]\n"
                    "  Read mails from one ore more POP3 accounts and deliver "
                    "them.\n"), prgname, prgname);
        printf(_("Server information mode:\n"
                    "  %s [option...] --serverinfo account...\n"
                    "  %s --host=host [option...] --serverinfo\n"
                    "  Print information about one or more POP3 servers.\n\n"), prgname, prgname);
        printf(_("General options:\n"));
        printf(_("  --version                    print version\n"));
        printf(_("  --help                       print help\n"));
        printf(_("  -P, --pretend                print configuration info and exit\n"));
        printf(_("  -d, --debug                  print debugging information\n"));
        printf(_("Changing the mode of operation:\n"));
        printf(_("  --configure=mailaddress      generate and print configuration for address\n"));
        printf(_("  -S, --serverinfo             print information about the server\n"));
        printf(_("Configuration options:\n"));
        printf(_("  -C, --file=filename          set configuration file\n"));
        printf(_("  --host=hostname              set the server, use only command-line settings;\n"
                    "                               do not use any configuration file data\n"));
        printf(_("  --port=number                set port number\n"));
        printf(_("  --proxy-host=[IP|hostname]   set/unset proxy\n"));
        printf(_("  --proxy-port=[number]        set/unset proxy port\n"));
        printf(_("  --source-ip=[IP]             set/unset source ip address to bind the socket to\n"));
        printf(_("  --timeout=(off|seconds)      set/unset network timeout in seconds\n"));
        printf(_("  --pipelining=(auto|on|off)   enable/disable pipelining\n"));
        printf(_("  --received-header[=(on|off)] enable/disable Received-header\n"));
        printf(_("  --auth[=(on|method)]         choose the authentication method\n"));
        printf(_("  --user=[username]            set/unset user name for authentication\n"));
        printf(_("  --passwordeval=[eval]        evaluate password for authentication\n"));
        printf(_("  --tls[=(on|off)]             enable/disable TLS encryption\n"));
        printf(_("  --tls-starttls[=(on|off)]    enable/disable STARTTLS for TLS\n"));
        printf(_("  --tls-trust-file=[file]      set/unset trust file for TLS\n"));
        printf(_("  --tls-crl-file=[file]        set/unset revocation file for TLS\n"));
        printf(_("  --tls-fingerprint=[f]        set/unset trusted certificate fingerprint for TLS\n"));
        printf(_("  --tls-key-file=[file]        set/unset private key file for TLS\n"));
        printf(_("  --tls-cert-file=[file]       set/unset private cert file for TLS\n"));
        printf(_("  --tls-certcheck[=(on|off)]   enable/disable server certificate checks for TLS\n"));
        printf(_("  --tls-min-dh-prime-bits=[b]  set/unset minimum bit size of DH prime\n"));
        printf(_("  --tls-priorities=[prios]     set/unset TLS priorities.\n"));
        printf(_("Options specific to mail retrieval mode:\n"));
        printf(_("  -q, --quiet                  do not display status or progress information\n"));
        printf(_("  -Q, --half-quiet             display status but not progress information\n"));
        printf(_("  -a, --all-accounts           query all accounts in the configuration file\n"));
        printf(_("  -A, --auth-only              authenticate only; do not retrieve mail\n"));
        printf(_("  -s, --status-only            print account status only; do not retrieve mail\n"));
        printf(_("  -n, --only-new[=(on|off)]    process only new messages\n"));
        printf(_("  -k, --keep[=(on|off)]        do not delete mails from servers\n"));
        printf(_("  --killsize=(off|number)      set/unset kill size\n"));
        printf(_("  --skipsize=(off|number)      set/unset skip size\n"));
        printf(_("  --filter=[program]           set/unset header filter\n"));
        printf(_("  --delivery=method,arg        set the mail delivery method\n"));
        printf(_("  --uidls-file=filename        set file to store UIDLs\n"));
        printf(_("\nReport bugs to <%s>.\n"), PACKAGE_BUGREPORT);
    }

    if (configure)
    {
        char *userconfigfile = conffile ? xstrdup(conffile) : get_userconfig(CONFFILE);
        error_code = mpop_configure(configure_address, userconfigfile);
        free(userconfigfile);
        free(configure_address);
        goto exit;
    }

    if (print_help || print_version
            || (!retrmail && !serverinfo && !print_conf))
    {
        error_code = EX_OK;
        goto exit;
    }

    /* get the list of account ids from the command line */
    accountidc = argc - optind;
    accountidv = &(argv[optind]);
    if (cmdline_account->host && (accountidc > 0 || all_accounts))
    {
        print_error(_("cannot use both --host and accounts"));
        error_code = EX_USAGE;
        goto exit;
    }
    if (all_accounts && accountidc > 0)
    {
        print_error(_("cannot use both --all-accounts and a list of accounts"));
        error_code = EX_USAGE;
        goto exit;
    }

    /* get the list of accounts to use into 'account_list'. */
    if (!cmdline_account->host)
    {
        if (!conffile)
        {
            conffile = get_userconfig(CONFFILE);
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
                        all_accounts ? -1 : accountidc, accountidv,
                        &account_list)) != 0)
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
        if (!account->password && account->passwordeval)
        {
            if (get_password_eval(account->passwordeval,
                        &account->password, &errstr) != CONF_EOK)
            {
                print_error("%s", mpop_sanitize_string(errstr));
                error_code = EX_CONFIG;
                goto exit;
            }
        }
        /* fill in last defaults */
        if (account->port == 0)
        {
            if (account->tls && account->tls_nostarttls)
            {
                account->port = 995;
            }
            else
            {
                account->port = 110;
            }
        }
        if (!account->tls_trust_file && !(account->mask & ACC_TLS_TRUST_FILE))
        {
            account->tls_trust_file = xstrdup("system");
        }
        if (account->proxy_host && account->proxy_port == 0)
        {
            account->proxy_port = 1080;
        }
        if (!account->uidls_file)
        {
            account->uidls_file = get_filename(homedir, UIDLSFILE);
        }
        /* check for consistency and completeness */
        if (check_account(account, retrmail, &errstr) != CONF_EOK)
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
        /* construct the complete, absolute UIDLS file name */
        account->uidls_file = string_replace(account->uidls_file, "%U",
                account->username ? account->username : "");
        account->uidls_file = string_replace(account->uidls_file, "%H",
                account->host);
        /* create directories needed for uidls_file */
        if (retrmail && !pretend && make_needed_dirs(account->uidls_file) != 0)
        {
            print_error(_("cannot create directories for %s: %s"),
                    account->uidls_file,
                    errno == ENOTDIR
                    ? _("a component already exists but is not a directory")
                    : strerror(errno));
            error_code = EX_IOERR;
            goto exit;
        }
    }

    /* print configuration */
    if (print_conf)
    {
        char fingerprint_string[2 * 32 + 31 + 1];

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
            printf("host = %s\n", account->host);
            printf("port = %d\n", account->port);
            printf("source ip = %s\n",
                    account->source_ip ? account->source_ip : _("(not set)"));
            printf("proxy host = %s\n",
                    account->proxy_host ? account->proxy_host : _("(not set)"));
            printf("proxy port = %d\n", account->proxy_port);
            printf("timeout = ");
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
            printf("pipelining = %s\n",
                    account->pipelining == 0 ? _("off")
                    : account->pipelining == 1 ? _("on") : _("auto"));
            printf("received_header = %s\n",
                    account->received_header ? _("on") : _("off"));
            printf("auth = ");
            if (account->auth_mech[0] == '\0')
            {
                printf(_("choose\n"));
            }
            else
            {
                printf("%s\n", account->auth_mech);
            }
            printf("user = %s\n",
                    account->username ? account->username : _("(not set)"));
            printf("password = %s\n", account->password ? "*" : _("(not set)"));
            printf("passwordeval = %s\n", account->passwordeval
                    ? account->passwordeval : _("(not set)"));
            printf("ntlmdomain = %s\n",
                    account->ntlmdomain ? account->ntlmdomain : _("(not set)"));
            printf("tls = %s\n", account->tls ? _("on") : _("off"));
            printf("tls_starttls = %s\n", account->tls_nostarttls ? _("off") : _("on"));
            printf("tls_trust_file = %s\n", account->tls_trust_file
                    ? account->tls_trust_file : _("(not set)"));
            printf("tls_crl_file = %s\n", account->tls_crl_file
                    ? account->tls_crl_file : _("(not set)"));
            if (account->tls_sha256_fingerprint)
            {
                mpop_fingerprint_string(fingerprint_string,
                        account->tls_sha256_fingerprint, 32);
            }
            else if (account->tls_sha1_fingerprint)
            {
                mpop_fingerprint_string(fingerprint_string,
                        account->tls_sha1_fingerprint, 20);
            }
            else if (account->tls_md5_fingerprint)
            {
                mpop_fingerprint_string(fingerprint_string,
                        account->tls_md5_fingerprint, 16);
            }
            printf("tls_fingerprint = %s\n",
                    account->tls_sha256_fingerprint
                    || account->tls_sha1_fingerprint || account->tls_md5_fingerprint
                    ? fingerprint_string : _("(not set)"));
            printf("tls_key_file = %s\n", account->tls_key_file
                    ? account->tls_key_file : _("(not set)"));
            printf("tls_cert_file = %s\n", account->tls_cert_file
                    ? account->tls_cert_file : _("(not set)"));
            printf("tls_certcheck = %s\n",
                    account->tls_nocertcheck ? _("off") : _("on"));
            printf("tls_min_dh_prime_bits = ");
            if (account->tls_min_dh_prime_bits >= 0)
            {
                printf("%d\n", account->tls_min_dh_prime_bits);
            }
            else
            {
                printf("%s\n", _("(not set)"));
            }
            printf("tls_priorities = %s\n", account->tls_priorities
                    ? account->tls_priorities : _("(not set)"));
            if (retrmail)
            {
                printf("delivery = ");
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
                else if (account->delivery_method == DELIVERY_METHOD_EXCHANGE)
                {
                    printf("exchange");
                }
                printf(" %s\n", account->delivery_args);
                printf("uidls file = %s\n", account->uidls_file);
                printf("only_new = %s\n",
                        account->only_new ? _("on") : _("off"));
                printf("keep = %s\n", account->keep ? _("on") : _("off"));
                printf("killsize = ");
                if (account->killsize < 0)
                {
                    printf(_("off\n"));
                }
                else
                {
                    printf(PRINTFLLD "\n", account->killsize);
                }
                printf("skipsize = ");
                if (account->skipsize < 0)
                {
                    printf(_("off\n"));
                }
                else
                {
                    printf(PRINTFLLD "\n", account->skipsize);
                }
                printf("filter = %s\n",
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
#ifdef HAVE_TLS
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
#else /* not HAVE_TLS */
            print_error(_("support for TLS is not compiled in"));
            error_code = EX_UNAVAILABLE;
            goto exit;
#endif /* HAVE_TLS */
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
        mpop_retrmail_abort = 0;
        lp = lp->next;
        account = lp->data;
        if (serverinfo)
        {
            e = mpop_serverinfo(account, debug, &errmsg, &errstr);
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
#if HAVE_SIGACTION
            signal_handler.sa_handler = mpop_retrmail_signal_handler;
            sigemptyset(&signal_handler.sa_mask);
            signal_handler.sa_flags = 0;
            (void)sigaction(SIGTERM, &signal_handler, &old_sigterm_handler);
            (void)sigaction(SIGHUP, &signal_handler, &old_sighup_handler);
            (void)sigaction(SIGINT, &signal_handler, &old_sigint_handler);
#elif HAVE_SIGNAL
            old_sigterm_handler = signal(SIGTERM, mpop_retrmail_signal_handler);
            old_sigint_handler = signal(SIGINT, mpop_retrmail_signal_handler);
#ifdef SIGHUP /* Windows supports SIGTERM and SIGINT, but not SIGHUP */
            old_sighup_handler = signal(SIGHUP, mpop_retrmail_signal_handler);
#endif
#endif
            e = mpop_retrmail(canonical_hostname, local_user,
                    account, debug, print_status, print_progress,
                    auth_only, status_only, &errmsg, &errstr);
#if HAVE_SIGACTION
            (void)sigaction(SIGTERM, &old_sigterm_handler, NULL);
            (void)sigaction(SIGHUP, &old_sighup_handler, NULL);
            (void)sigaction(SIGINT, &old_sigint_handler, NULL);
#elif HAVE_SIGNAL
            (void)signal(SIGTERM, old_sigterm_handler);
            (void)signal(SIGINT, old_sigint_handler);
#ifdef SIGHUP /* Windows supports SIGTERM and SIGINT, but not SIGHUP */
            (void)signal(SIGHUP, old_sighup_handler);
#endif
#endif
        }
        if (e != EX_OK)
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
            if (!serverinfo) /* retrmail */
            {
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
            if (error_code == EX_OK)
            {
                /* this is the first error in the list of accounts */
                error_code = e;
            }
            else
            {
                /* a previous account already generated an error; whenever
                 * more than one account fails, we return a generic error */
                error_code = EX_TEMPFAIL;
            }
        }
        if (mpop_retrmail_abort)
        {
            break;
        }
    }
    free(canonical_hostname);
    free(local_user);

exit:
    /* clean up */
    free(errstr);
    free(errmsg);
    free(homedir);
#ifdef HAVE_TLS
    if (tls_lib_initialized)
    {
        tls_lib_deinit();
    }
#endif /* HAVE_TLS */
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
