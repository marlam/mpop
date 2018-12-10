/*
 * pop3.h
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2014, 2015,
 * 2016, 2018
 * Martin Lambers <marlam@marlam.de>
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

#ifndef POP3_H
#define POP3_H

#include <stdio.h>
#include <signal.h>

#include "readbuf.h"
#include "net.h"
#ifdef HAVE_TLS
# include "tls.h"
#endif /* HAVE_TLS */


/* POP3 errors */

/*
 * If a function with an 'errstr' argument returns a value != CONF_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * Likewise, if a function takes an 'errmsg' argument and returns a value !=
 * POP3_EOK, '*errmsg' either points to the POP3 server error message in an
 * allocated string or is NULL.
 * If such a function returns POP3_EOK, neither 'errmsg' nor 'errstr' will be
 * changed.
 */
#define POP3_EOK                0       /* no error */
#define POP3_EIO                1       /* Input/output error */
#define POP3_EPROTO             2       /* Protocol violation */
#define POP3_EINVAL             3       /* Invalid input data */
#define POP3_EUNAVAIL           4       /* Requested service unavailable */
#define POP3_EAUTHFAIL          5       /* Authentication failed */
#define POP3_ELIBFAILED         6       /* An underlying library failed */
#define POP3_EINSECURE          7       /* The requested action would be
                                           insecure */
#define POP3_EDELIVERY          8       /* Mail delivery failed */
#define POP3_EABORT             9       /* The current action was aborted */

/* POP3 capabilities */
#define POP3_CAP_AUTH_USER              (1 << 0)
#define POP3_CAP_AUTH_APOP              (1 << 1)
#define POP3_CAP_AUTH_PLAIN             (1 << 2)
#define POP3_CAP_AUTH_CRAM_MD5          (1 << 3)
#define POP3_CAP_AUTH_DIGEST_MD5        (1 << 4)
#define POP3_CAP_AUTH_SCRAM_SHA_1       (1 << 5)
#define POP3_CAP_AUTH_GSSAPI            (1 << 6)
#define POP3_CAP_AUTH_EXTERNAL          (1 << 7)
#define POP3_CAP_AUTH_LOGIN             (1 << 8)
#define POP3_CAP_AUTH_NTLM              (1 << 9)
#define POP3_CAP_CAPA                   (1 << 10)
#define POP3_CAP_TOP                    (1 << 11)
#define POP3_CAP_LOGIN_DELAY            (1 << 12)
#define POP3_CAP_PIPELINING             (1 << 13)
#define POP3_CAP_EXPIRE                 (1 << 14)
#define POP3_CAP_UIDL                   (1 << 15)
#define POP3_CAP_IMPLEMENTATION         (1 << 16)
#define POP3_CAP_STLS                   (1 << 17)
#define POP3_CAP_RESP_CODES             (1 << 18)
#define POP3_CAP_AUTH_RESP_CODE         (1 << 19)

/*
 * Buffer size for communication with the POP3 server. This restricts the length
 * of POP3 command lines, but does not restrict the length of lines allowed in
 * mails. Nevertheless, it should be greater than 1000, so that a line of the
 * maximum length allowed by RFC 2822 can fit entirely into it.
 */
#define POP3_BUFSIZE 1024

/*
 * This structure describes the capabilities of a POP3 server.
 * 'flags' is a combination of the POP3_CAP_* values above.
 * If (flags & POP3_CAP_AUTH_APOP), 'apop_timestamp' contains the APOP timestamp
 * string.
 * If (flags & POP3_CAP_LOGIN_DELAY), 'login_delay' contains the minimum number
 * of seconds required between to sessions.
 * If (flags & POP3_CAP_EXPIRE), 'expire' contains the minimum retention time of
 * the server in days. 0 means that no mail may be left on the server, LONG_MAX
 * means that the server does not delete mails automatically.
 * If (flags & POP3_CAP_IMPLEMENTATION), 'implementation' contains the POP3
 * server implementation identification string (untrusted data!).
 * If not (flags & POP3_CAP_CAPA), the flags are probably incomplete - it is
 * unknown whether for example the UIDL command is supported.
 */
typedef struct
{
    int flags;
    long login_delay;
    long expire;
    char *implementation;
    char *apop_timestamp;
} pop3_cap_t;


/*
 *
 * This structure represents a POP3 session.
 *
 *
 * The "session information" section can be accessed outside of pop3.c.
 *
 * The first function that handles session information is pop3_stat().
 * It fills in:
 * - total_number
 * - total_size (not reliable! may be zero even when total_number > 0)
 * - msg_action (all initialized to POP3_MSG_ACTION_NORMAL)
 * - is_old (all initialized to false)
 * - new_number (= total_number)
 * - new_size (= total_size, not reliable, see above)
 * The next function is pop3_uidl():
 * - msg_uid (UID of each mail)
 * With this information, the caller can update the session fields of each mail:
 * Given a list of UIDs of previously retrieved mails, it can update:
 * - is_old (set true for retrieved mails)
 * - msg_action (probably set to POP3_MSG_ACTION_IGNORE for retrieved mails)
 * - old_number
 * - new_number
 * - new_size (may not be reliable)
 * The filtering step is optional. It can make further changes to the msg_action
 * field.
 * The next step is retrieving and delivering with pop3_retr().
 * - only mails with the action POP3_MSG_ACTION_NORMAL will be retrieved and
 *   delivered
 * - if a mail is successfully delivered, the is_old flag will be set, and the
 *   action changed to POP3_MSG_ACTION_DELETE
 * - old_number is updated
 * If the caller wants to delete all mails that are now marked with action
 * POP3_MSG_ACTION_DELETE, he can call pop3_dele(). This function
 * - unsets the is_old flag for each deleted message
 * - updates old_number,
 * The caller can then save the UIDs of all mails marked is_old into a file, so
 * that these mails are not retrieved again if this is undesirable.
 */

/* The message action is one of the following: */
#define POP3_MSG_ACTION_NORMAL          0       /* proceed normally */
#define POP3_MSG_ACTION_IGNORE          1       /* ignore this mail */
#define POP3_MSG_ACTION_DELETE          2       /* delete this mail */

typedef struct
{
    /* Information about the local system */
    char *local_hostname;       /* A canonical name of this host */
    char *local_user;           /* The (login) name of the user for which mails
                                   are retrieved in this session */
    /* The POP3 server */
    char *server_hostname;      /* the hostname of the POP3 server as given by
                                   the user */
    char *server_canonical_name;/* the canonical hostname of the POP3 server
                                   connected with 'fd' */
    char *server_address;       /* network address of the POP3 server connected
                                   with 'fd', in human readable form */
    pop3_cap_t cap;             /* capabilities of the POP3 server */
    int pipelining;             /* pipelining: 0=off, 1=on, 2=auto */
    int count_newline_as_crlf;  /* does the server count newline as 2 chars? */
    int fd;                     /* the socket */
#ifdef HAVE_TLS
    tls_t tls;                  /* TLS descriptor */
#endif /* HAVE_TLS */
    char buffer[POP3_BUFSIZE];  /* input/output buffer */
    readbuf_t readbuf;          /* net input buffering */
    FILE *debug;                /* stream for debugging output, or NULL */

    /* POP3 session information */
    long total_number;          /* total number of messages */
    long long total_size;       /* total size of messages */
    unsigned char *is_old;      /* this message a) has been retrieved before and
                                   b) is not deleted */
    long old_number;            /* number of messages for which is_old is set */
    long new_number;            /* number of new messages */
    long long new_size;         /* size of new messages */
    unsigned char *msg_action;  /* action for each mail */
    char **msg_uid;             /* UID of each mail */
    long long *msg_size;        /* size of each mail */
} pop3_session_t;


/*
 * pop3_session_new()
 *
 * Create a new pop3_session_t. 'canonical_hostname' must be a name of this host
 * that is meaningful to other hosts. Ideally it is the full qualified domain
 * name of this host. 'local_user' must be the login name of the user for
 * which mail will be retrieved during this session. Both strings are only used
 * when mail is retrieved and delivered, so if this session will not be used to
 * actually retrieve any mail, these values may be empty strings.
 * Pipelining will be enabled/disabled according to 'pipelining': 0 means off, 1
 * means on, and auto means to enable it for servers that advertize the
 * PIPELINING capability in response to the CAPA command and disable it for all
 * other servers.
 * If 'debug' is not NULL, the complete conversation with the POP3 server will
 * be logged to the referenced file.
 * Beware: this log may contain user passwords.
 */
pop3_session_t *pop3_session_new(int pipelining,
        const char *canonical_hostname, const char *local_user,
        FILE *debug);

/*
 * pop3_session_free()
 *
 * Free a pop3_session_t.
 */
void pop3_session_free(pop3_session_t *session);

/*
 * pop3_connect()
 *
 * Connect to a POP3 server.
 * If 'server_canonical_name' is not NULL, a pointer to a string containing the
 * canonical hostname of the server will be stored in '*server_canonical_name',
 * or NULL if this information is not available.
 * If 'server_address' is not NULL, a pointer to a string containing the
 * network address of the server will be stored in '*server_address',
 * or NULL if this information is not available.
 * The strings must not be deallocated.
 * Used error codes: NET_EHOSTNOTFOUND, NET_ESOCKET, NET_ECONNECT, NET_EPROXY
 */
int pop3_connect(pop3_session_t *session,
        const char *proxy_hostname, int proxy_port,
        const char *server_hostname, int port, const char *source_ip, int timeout,
        const char **server_canonical_name, const char **server_address,
        char **errstr);

/*
 * pop3_get_greeting()
 *
 * Get the initial greeting string from a POP3 server.
 * This function alters session->cap.
 * If 'greeting' is not NULL, it must point to a buffer which is at least
 * POP3_BUFSIZE - 4 characters long. This buffer will contain the
 * identificatin string of the POP3 server (untrusted data!)
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_get_greeting(pop3_session_t *session, char *greeting,
        char **errmsg, char **errstr);

/*
 * pop3_capa()
 *
 * Sends the CAPA command to the POP3 server and determines the capabilities
 * of the POP3 server. If after the first call to this function the
 * POP3_CAP_CAPA flag is not set, don't call it again: the server does not
 * support the CAPA command.
 * The capability flags will not be resetted before adding capabilities, so
 * capabilities that were set in previous calls to CAPA (in other POP3 states)
 * will still be set.
 * If session->pipelining is 2 ("auto"), then this command will alter it:
 * it will be set to 1 ("on") if the server supports CAPA and advertizes
 * PIPELINING, and to 0 ("off") in all other cases.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_capa(pop3_session_t *session, char **errstr);

/*
 * pop3_tls_init()
 *
 * Prepare TLS encryption. See tls_init() for a description of the arguments.
 * Used error codes: TLS_ELIBFAILED, TLS_EFILE
 */
#ifdef HAVE_TLS
int pop3_tls_init(pop3_session_t *session,
        const char *tls_key_file, const char *tls_cert_file,
        const char *tls_trust_file, const char *tls_crl_file,
        const unsigned char *tls_sha256_fingerprint,
        const unsigned char *tls_sha1_fingerprint,
        const unsigned char *tls_md5_fingerprint,
        int min_dh_prime_bits, const char *priorities,
        char **errstr);
#endif /* HAVE_TLS */

/*
 * pop3_tls_stls()
 *
 * Announce the start of TLS encryption with a POP3 server, using the STLS
 * command.
 * Use this function after pop3_capa(). The POP3 server must have the
 * POP3_CAP_STLS capability.
 * Call pop3_tls() afterwards. Finally, call pop3_capa() again (the POP3 server
 * might advertise different capabilities when TLS is active, for example plain
 * text authentication mechanisms).
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
#ifdef HAVE_TLS
int pop3_tls_stls(pop3_session_t *session, char **errmsg, char **errstr);
#endif /* HAVE_TLS */

/*
 * pop3_tls()
 *
 * Start TLS with a connected POP3 server.
 * Use this function after pop3_connect().
 * See tls_start() for a description of the arguments.
 * Used error codes: TLS_ELIBFAILED, TLS_ECERT, TLS_EHANDSHAKE
 */
#ifdef HAVE_TLS
int pop3_tls(pop3_session_t *session, const char *hostname, int tls_nocertcheck,
        tls_cert_info_t *tci, char **tls_parameter_description, char **errstr);
#endif /* HAVE_TLS */

/*
 * pop3_client_supports_authmech()
 *
 * Returns 1 if the authentication mechanism is supported by the underlying
 * authentication code and 0 otherwise.
 */
int pop3_client_supports_authmech(const char *mech);

/*
 * pop3_server_supports_authmech()
 *
 * Returns 1 if the authentication mechanism is supported by the POP3 server
 * and 0 otherwise.
 */
int pop3_server_supports_authmech(pop3_session_t *session, const char *mech);

/*
 * pop3_auth()
 *
 * Authentication.
 * Use pop3_client_supports_authmech() and pop3_server_supports_authmech()
 * to find out which authentication mechanisms are available.
 * The special value "" for 'auth_mech' causes the function to choose the best
 * authentication method supported by the server, unless TLS is inactive and the
 * method sends plain text passwords. In this case, the function fails with
 * POP3_EINSECURE.
 * The hostname is the name of the POP3 server. It may be needed for
 * authentication.
 * The ntlmdomain may be NULL (even if you use NTLM authentication).
 * If 'password' is NULL, but the authentication method needs a password,
 * the 'password_callback' function is called (if 'password_callback' is not
 * NULL). It is expected to return a * password in an allocated buffer or NULL
 * (if it fails).
 * Used error codes: POP3_EIO, POP3_EINVAL, POP3_EPROTO
 *                   POP3_EAUTHFAIL, POP3_ELIBFAILED, POP3_EINSECURE,
 *                   POP3_EUNAVAIL
 */
int pop3_auth(pop3_session_t *session,
        const char *auth_mech,
        const char *user,
        const char *password,
        const char *hostname,
        const char *ntlmdomain,
        char *(*password_callback)(const char *hostname, const char *user),
        char **errmsg,
        char **errstr);

/*
 * pop3_stat()
 *
 * Issues the POP3 STAT command.
 * This initializes the following fields of 'session':
 * - total_number
 * - total_size (not reliable! may be zero even when total_number > 0)
 * - msg_action (all initialized to POP3_MSG_ACTION_NORMAL)
 * - is_old (all initialized to false)
 * - new_number (= total_number)
 * - new_size (= total_size, not reliable, see above)
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL, POP3_ELIBFAILED
 */
int pop3_stat(pop3_session_t *session, char **errmsg, char **errstr);

/*
 * pop3_uidl()
 *
 * Issues the POP3 UIDL command without an argument.
 * This initializes the following fields of 'session':
 * - msg_uid
 * If 'abort' is externally set, this function will abort and return
 * POP3_EABORTED. The POP3 session is not usable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL, POP3_EUNAVAIL.
 * The error POP3_EUNAVAIL is not critical: it means that the POP3 server does
 * not support the UIDL command.
 */
int pop3_uidl(pop3_session_t *session, char **uidv, long uidv_len, int only_new,
        volatile sig_atomic_t *abort, char **errmsg, char **errstr);

/*
 * pop3_list()
 *
 * Issues the POP3 LIST command without an argument.
 * This initializes the following fields of 'session':
 * - msg_size
 * If 'abort' is externally set, this function will abort and return
 * POP3_EABORTED. The POP3 session is not usable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_list(pop3_session_t *session, volatile sig_atomic_t *abort,
        char **errmsg, char **errstr);

/*
 * pop3_filter()
 *
 * Issues the POP3 TOP command for all messages whose action is
 * POP3_MSG_ACTION_NORMAL.
 * The header, and the blank line separating header and body, will be piped
 * to 'filtercmd'.
 * The exit status will be interpreted as follows:
 * 0   - proceed normally
 * 1   - change message action to POP3_MSG_ACTION_DELETE
 * 2   - change message action to POP3_MSG_ACTION_IGNORE
 * >=3 - an error occurred. Exit codes from sysexits.h are supported.
 * If the action changed and filter_output is not NULL, the output function will
 * be called. 'data' can point to arbitrary user data that is passed to the
 * output function.
 * If 'abort' is externally set, this function will abort and return
 * POP3_EABORTED. The POP3 session is not usable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL, POP3_EDELIVERY,
 * POP3_EABORT.
 */
int pop3_filter(pop3_session_t *session, volatile sig_atomic_t *abort,
        const char *filtercmd,
        void (*filter_output)(long i, long number, int new_action, void *data),
        void *data, char **errmsg, char **errstr);

/*
 * pop3_retr()
 *
 * Issues the POP3 RETR command for all messages whose action is
 * POP3_MSG_ACTION_NORMAL.
 * The mail will be delivered with the method specified by 'delivery_method' and
 * 'delivery_method_arguments'. An exit status > 0 will be interpreted as an
 * error. Exit codes from sysexits.h are supported. If 'pipecmd' returns zero,
 * the mesage action will be changed to POP3_MSG_ACTION_DELETE, and is_old will
 * be set for this message. old_number will be updated.
 * A Received header will be prepended to the mail if the
 * 'write_received_header' flag is set.
 * If the progress functions are not NULL, they will be called:
 * - 'progress_begin' once, before anything is retrieved
 * - 'progress' 99 times, while retrieving the mail, with 'percent' increasing
 *    from 1 to 99
 * - 'progress_end' once, after everything was retrieved successfully
 * - 'progress_abort' only if an error occurred, to clean up the output
 * If 'abort' is externally set, this function will abort and return
 * POP3_EABORTED. The POP3 session is not usable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL, POP3_EDELIVERY,
 * POP3_EABORT
 */
int pop3_retr(pop3_session_t *session, volatile sig_atomic_t *abort,
        int delivery_method, const char *delivery_method_arguments,
        int write_received_header,
        void (*progress_start)(long i, long number, long long size),
        void (*progress)(long i, long number, long long rcvd, long long size,
            int percent),
        void (*progress_end)(long i, long number, long long size),
        void (*progress_abort)(long i, long number, long long size),
        char **errmsg, char **errstr);

/*
 * pop3_dele()
 *
 * Issues the POP3 DELE command for all messages whose action is
 * POP3_MSG_ACTION_DELETE.
 * If it was set before, the is_old flag will be unset for each deleted message,
 * and old_number will be updated.
 * If 'abort' is externally set, this function will abort and return
 * POP3_EABORTED. The POP3 session is not usable thereafter.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_dele(pop3_session_t *session, volatile sig_atomic_t *abort,
        char **errmsg, char **errstr);

/*
 * pop3_rset()
 *
 * Sends the RSET command to the POP3 server to reset the current session.
 * This is an emergency break that should be followed by pop3_quit(),
 * pop3_close() and pop3_session_free(): the session information is not updated
 * and thus useless.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_rset(pop3_session_t *session, char **errmsg, char **errstr);

/*
 * pop3_quit()
 *
 * Sends the QUIT command to the POP3 server to end the current session.
 * Use pop3_close() after this function.
 * Used error codes: POP3_EIO, POP3_EPROTO, POP3_EINVAL
 */
int pop3_quit(pop3_session_t *session, char **errmsg, char **errstr);

/*
 * pop3_close()
 *
 * Closes the connection to the POP3 server.
 * Use pop3_session_free() afterwards.
 */
void pop3_close(pop3_session_t *session);

#endif
