/*
 * mpopd.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2021  Martin Lambers <marlam@marlam.de>
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

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <syslog.h>
#include <getopt.h>
extern char *optarg;
extern int optind;

#include "password.h"
#include "tools.h"
#include "xalloc.h"


/* Built-in defaults */
static const char* DEFAULT_INTERFACE = "127.0.0.1";
static const int DEFAULT_PORT = 1100;
static const int MAX_ACTIVE_SESSIONS = 16;
static const int AUTH_DELAY_SECONDS = 1;
static const int AUTH_DELAY_EXPIRATION_SECONDS = 60;
static const size_t POP3_BUFSIZE = 1024;

/* Logging */

typedef enum {
    log_info = 0,
    log_error = 1,
    log_nothing = 2
} log_level_t;

typedef struct {
    FILE* file; /* if NULL then use syslog */
    log_level_t level;
} log_t;

void log_open(int log_to_syslog, const char* log_file_name, log_t* log)
{
    log->file = NULL;
    log->level = log_info; /* default currently hard-coded */
    int log_file_open_failure = 0;
    if (log_file_name) {
        log->file = fopen(log_file_name, "a");
        if (!log->file) {
            log_file_open_failure = 1;
            log_to_syslog = 1;
        }
    }
    if (log_to_syslog) {
        openlog("mpopd", LOG_PID, LOG_MAIL);
        if (log_file_open_failure)
            syslog(LOG_ERR, "cannot open log file, using syslog instead");
    }
    if (!log_file_name && !log_to_syslog) {
        log->level = log_nothing;
    }
}

void log_close(log_t* log)
{
    if (log->level < log_nothing) {
        if (log->file)
            fclose(log->file);
        else
            closelog();
    }
}

void
#ifdef __GNUC__
__attribute__ ((format (printf, 3, 4)))
#endif
log_msg(log_t* log,
        log_level_t msg_level,
        const char* msg_format, ...)
{
    if (msg_level >= log->level) {
        if (log->file) {
            long long pid = getpid();
            time_t t = time(NULL);
            struct tm* tm = localtime(&t);
            char time_str[128];
            strftime(time_str, sizeof(time_str), "%F %T", tm);
            fprintf(log->file, "%s mpopd[%lld] %s: ", time_str, pid,
                    msg_level >= log_error ? "error" : "info");
            va_list args;
            va_start(args, msg_format);
            vfprintf(log->file, msg_format, args);
            va_end(args);
            fputc('\n', log->file);
        } else {
            int priority = (msg_level >= log_error ? LOG_ERR : LOG_INFO);
            va_list args;
            va_start(args, msg_format);
            vsyslog(priority, msg_format, args);
            va_end(args);
        }
    }
}

/* Representation of one mail */
typedef struct {
    char* filename;
    char* uid;
    unsigned long long size;
    struct timespec mtime;
    int marked_as_deleted;
} mail_t;

int mail_compare_mtime(const void* m1, const void* m2)
{
    const mail_t* mail1 = m1;
    const mail_t* mail2 = m2;

    int cmp;
    if (mail1->mtime.tv_sec < mail2->mtime.tv_sec) {
        cmp = -1;
    } else if (mail1->mtime.tv_sec == mail2->mtime.tv_sec) {
        if (mail1->mtime.tv_nsec < mail2->mtime.tv_nsec) {
            cmp = -1;
        } else if (mail1->mtime.tv_nsec == mail2->mtime.tv_nsec) {
            /* In this unlikely case, we additionally look at the uid
             * (which cannot be identical) so that the mail ordering
             * is consistent between sessions even if time stamps
             * match exactly. */
            cmp = strcmp(mail1->uid, mail2->uid);
        } else {
            cmp = +1;
        }
    } else {
        cmp = +1;
    }
    return cmp;
}

/* Representation of the session state */
typedef struct {
    FILE* lockf;
    unsigned long long mail_count;
    mail_t* mails;
} session_t;

void init_session(session_t* session)
{
    session->lockf = NULL;
    session->mail_count = 0;
    session->mails = NULL;
}

/* Get an adivsory lock on the mailbox */
FILE* get_lock(const char* lockfile)
{
    FILE* lockf = fopen(lockfile, "w");
    if (!lockf)
        return NULL;
    int lockfd = fileno(lockf);
    struct flock lock;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    if (fcntl(lockfd, F_SETLK, &lock) != 0) {
        fclose(lockf);
        return NULL;
    }
    return lockf;
}

/* Get the adivsory lock on the mailbox */
void release_lock(FILE* lockf)
{
    int lockfd = fileno(lockf);
    struct flock lock;
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 0;
    fcntl(lockfd, F_SETLK, &lock);
    fclose(lockf);
}

/* Initialize POP3 session by locking the mailbox and reading its current state */
int initialize_authorized_session(session_t* session, const char* maildir)
{
    init_session(session);

    /* Get exclusive adisory lock */
    const char* lockfilebasename = "mpopd.lock";
    char* lockfilename = malloc(strlen(maildir) + 1 + strlen(lockfilebasename) + 1);
    if (!lockfilename)
        return 1;
    strcpy(lockfilename, maildir);
    strcat(lockfilename, "/");
    strcat(lockfilename, lockfilebasename);
    session->lockf = get_lock(lockfilename);
    free(lockfilename);
    if (!session->lockf)
        return 1;

    /* Read the maildir contents */
    char* maildirnew = malloc(strlen(maildir) + 4 + 1);
    if (!maildirnew) {
        release_lock(session->lockf);
        return 1;
    }
    strcpy(maildirnew, maildir);
    strcat(maildirnew, "/new");
    DIR* dir = opendir(maildirnew);
    errno = 0;
    struct dirent* dirent;
    while ((dirent = readdir(dir)) != NULL) {
        char* mailfilename = malloc(strlen(maildirnew) + 1 + strlen(dirent->d_name) + 1);
        if (!mailfilename) {
            /* ignore additional mails because we have ENOMEM */
            break;
        }
        strcpy(mailfilename, maildirnew);
        strcat(mailfilename, "/");
        strcat(mailfilename, dirent->d_name);
        struct stat statbuf;
        if (stat(mailfilename, &statbuf) == 0
                && ((statbuf.st_mode & S_IFMT) == S_IFREG)) {
            if (session->mail_count == SIZE_MAX / sizeof(mail_t)) {
                /* ignore additional mails in this session to prevent overflow */
                free(mailfilename);
                break;
            }
            mail_t mail = { .filename = NULL, .uid = NULL, .size = 0, .marked_as_deleted = 0 };
            mail.filename = mailfilename;
            mail.uid = strdup(dirent->d_name);
            if (!mail.uid) {
                /* ignore additional mails because we have ENOMEM */
                free(mailfilename);
                break;
            }
            mail.size = statbuf.st_size;
            mail.mtime.tv_sec = statbuf.st_mtim.tv_sec;
            mail.mtime.tv_nsec = statbuf.st_mtim.tv_nsec;
            session->mail_count += 1;
            /* TODO: having one realloc() per mail is inefficient; write a smarter function
             * to increase the array size in larger steps */
            mail_t* new_mail_array = realloc(session->mails, session->mail_count * sizeof(mail_t));
            if (!new_mail_array) {
                /* ignore additional mails because we have ENOMEM */
                free(mailfilename);
                break;
            }
            session->mails = new_mail_array;
            session->mails[session->mail_count - 1] = mail;
        } else {
            free(mailfilename);
        }
    }
    free(maildirnew);
    if (errno != 0) {
        release_lock(session->lockf);
        free(session->mails);
        init_session(session);
        return 1;
    }

    /* Sort mails according to their time of last modification (mtime)
     * so that they are presented to the client in the order one would expect. */
    qsort(session->mails, session->mail_count, sizeof(mail_t), mail_compare_mtime);

    return 0;
}

void end_authorized_session(session_t* session)
{
    release_lock(session->lockf);
    free(session->mails);
    init_session(session);
}


/* Read POP3 command from client */
int read_pop3_cmd(FILE* in, char* buf, int bufsize)
{
    if (!fgets(buf, bufsize, in))
        return 1;
    size_t len = strlen(buf);
    if (buf[len - 1] != '\n')
        return 1;
    buf[len - 1] = '\0';
    if (len - 1 > 0 && buf[len - 2] == '\r')
        buf[len - 2] = '\0';
    return 0;
}

/* Send CAPA response to client */
void send_pop3_capa_response(FILE* out)
{
    fprintf(out,
            "+OK\r\n"
            "USER\r\n"
            "UIDL\r\n"
            ".\r\n");
}

/* Send RETR response to client.
 * This is adapted from the msmtp smtp_send_mail(). */
int send_pop3_retr_response(FILE* in, FILE* out)
{
    char bigbuffer[POP3_BUFSIZE + 3]; /* buffer + leading dot + ending CRLF */
    char *buffer;
    size_t len;
    char *send_buf;
    size_t send_len;
    int in_header;
    int line_starts;
    int line_continues;

    bigbuffer[0] = '.';
    buffer = bigbuffer + 1;
    in_header = 1;
    line_continues = 0;
    if (!in)
        return 1;

    for (;;) {
        if (!fgets(buffer, POP3_BUFSIZE, in)) {
            if (ferror(in))
                return 1;
            else
                break;
        }
        len = strlen(buffer);
        if (len == 0)
            break;
        line_starts = !line_continues;
        if (len > 0 && buffer[len - 1] == '\n') {
            /* first case: we have a line end */
            buffer[--len] = '\0';
            if (len > 0 && buffer[len - 1] == '\r') {
                buffer[--len] = '\0';
            }
            line_continues = 0;
        } else if (len == POP3_BUFSIZE - 1) {
            /* second case: the line continues */
            if (buffer[len - 1] == '\r') {
                /* We have CRLF that is divided by the buffer boundary. Since CR
                 * may not appear alone in a mail according to RFC2822, we
                 * know that the next buffer will be "\n\0", so it's safe to
                 * just delete the CR. */
                buffer[--len] = '\0';
            }
            line_continues = 1;
        } else {
            /* third case: this is the last line, and it lacks a newline
             * character */
            line_continues = 0;
        }
        if (line_starts && in_header && buffer[0] == '\0') {
            in_header = 0;
        }
        /* TODO: if in_header is 0, we can start counting mail body lines
         * to implement the TOP command later. */
        send_buf = buffer;
        send_len = len;
        if (line_starts && buffer[0] == '.') {
            /* Quote the leading dot with another dot */
            send_buf = bigbuffer;
            send_len = len + 1;
        }
        if (!line_continues) {
            /* Append CRLF */
            buffer[len] = '\r';
            buffer[len + 1] = '\n';
            buffer[len + 2] = '\0';
            send_len += 2;
        }
        if (fputs(send_buf, out) == EOF) {
            return 1;
        }
    }
    if (fflush(out) != 0 || ferror(out)) {
        return 1;
    }

    return 0;
}

/* Get a message number from a string. Message numbers start at 1,
 * so if this function succeeds then n > 0. */
int get_message_number(const char* s, unsigned long long* n)
{
    if (!(s[0] >= '0' && s[0] <= '9')) {
        /* strtoull() would accept leading spaces and a plus or even a minus
         * sign; we don't want that here */
        return 1;
    }
    errno = 0;
    char* endptr;
    *n = strtoull(s, &endptr, 10);
    if (errno == ERANGE || (*endptr != '\0') || *n == 0) {
        return 1;
    }
    return 0;
}

/* Table of user/password pairs and corresponding maildir */
typedef struct {
    char* user;
    char* password;
    char* maildir;
} user_t;

/* POP3 session with input and output from FILE descriptors.
 *
 * Return value:
 * 0 if the session ended normally / successfully
 * 1 if the session had errors and/or was aborted
 * 2 same as 1 and the session had authentication failures
 */
int mpopd_session(log_t* log, FILE* in, FILE* out,
        const user_t* users, size_t user_count,
        int impose_auth_delay)
{
    char buf[POP3_BUFSIZE];
    char buf2[POP3_BUFSIZE];
    int authorized = 0;
    int authorization_failure_occurred = 0;
    session_t session;
    init_session(&session);

    setlinebuf(out);

    /* AUTHORIZATION state */
    log_msg(log, log_info, "starting POP3 session");
    fprintf(out, "+OK mpopd ready.\r\n");
    while (!authorized) {
        if (ferror(out)) {
            log_msg(log, log_error, "output error, session aborted");
            return authorization_failure_occurred ? 2 : 1;
        }
        if (read_pop3_cmd(in, buf, POP3_BUFSIZE) != 0) {
            log_msg(log, log_error, "input error, session aborted");
            return authorization_failure_occurred ? 2 : 1;
        }
        if (strcasecmp(buf, "QUIT") == 0) {
            fprintf(out, "+OK\r\n");
            log_msg(log, log_info, "client ended session");
            return authorization_failure_occurred ? 2 : 0;
        } else if (strcasecmp(buf, "CAPA") == 0) {
            send_pop3_capa_response(out);
            continue;
        } else if (strncasecmp(buf, "USER ", 5) == 0) {
            strcpy(buf2, buf + 5);
            log_msg(log, log_info, "client started authorization");
            fprintf(out, "+OK\r\n");
            if (read_pop3_cmd(in, buf, POP3_BUFSIZE) != 0) {
                log_msg(log, log_error, "input error, session aborted");
                return authorization_failure_occurred ? 2 : 1;
            }
            if (strncasecmp(buf, "PASS ", 5) == 0) {
                if (impose_auth_delay || authorization_failure_occurred)
                    sleep(AUTH_DELAY_SECONDS);
                /* user parameter is in buf2 and password parameter in buf + 5 */
                /* first find the corresponding user in the table */
                /* TODO: we could do binary search in a sorted array but it seems overkill */
                size_t user_index;
                for (user_index = 0; user_index < user_count; user_index++)
                    if (strcmp(buf2, users[user_index].user) == 0)
                        break;
                /* next check if the password matches too */
                if (user_index < user_count && strcmp(buf + 5, users[user_index].password) == 0) {
                    /* then try to initialize the session */
                    if (initialize_authorized_session(&session, users[user_index].maildir) == 0) {
                        authorized = 1;
                        fprintf(out, "+OK\r\n");
                        log_msg(log, log_info, "user %s authorized and mailbox locked",
                                users[user_index].user);
                    } else {
                        fprintf(out, "-ERR cannot access mailbox\r\n");
                        log_msg(log, log_info, "authorization for user %s failed: cannot lock mailbox",
                                users[user_index].user);
                    }
                } else {
                    authorization_failure_occurred = 1;
                    log_msg(log, log_info, "authorization for user %s failed: invalid credentials",
                            sanitize_string(buf2));
                    fprintf(out, "-ERR authorization failed\r\n");
                }
            }
        } else {
            fprintf(out, "-ERR command not understood\r\n");
            continue;
        }
    }

    /* TRANSACTION state */
    log_msg(log, log_info, "starting transaction phase with %llu mails in mailbox", session.mail_count);
    int error = 0;
    unsigned long long msgnum; /* message numbers start at 1! */
    for (;;) {
        if (ferror(out)) {
            log_msg(log, log_error, "output error, session aborted");
            error = 1;
            break;
        }
        if (read_pop3_cmd(in, buf, POP3_BUFSIZE) != 0) {
            log_msg(log, log_error, "input error, session aborted");
            error = 1;
            break;
        }
        if (strcasecmp(buf, "QUIT") == 0) {
            fprintf(out, "+OK\r\n");
            log_msg(log, log_info, "client ended transaction phase");
            break;
        } else if (strcasecmp(buf, "NOOP") == 0) {
            fprintf(out, "+OK\r\n");
        } else if (strcasecmp(buf, "CAPA") == 0) {
            send_pop3_capa_response(out);
        } else if (strcasecmp(buf, "RSET") == 0) {
            for (unsigned long long i = 0; i < session.mail_count; i++)
                session.mails[i].marked_as_deleted = 0;
            fprintf(out, "+OK\r\n");
        } else if (strcasecmp(buf, "STAT") == 0) {
            unsigned long long undeleted_mail_count = 0;
            unsigned long long undeleted_total_size = 0;
            for (unsigned long long i = 0; i < session.mail_count; i++) {
                if (!(session.mails[i].marked_as_deleted)) {
                    undeleted_mail_count++;
                    undeleted_total_size += session.mails[i].size;
                }
            }
            fprintf(out, "+OK %llu %llu\r\n",
                    undeleted_mail_count,
                    undeleted_total_size);
        } else if (strcasecmp(buf, "LIST") == 0) {
            fprintf(out, "+OK\r\n");
            for (unsigned long long i = 0; i < session.mail_count; i++) {
                if (!(session.mails[i].marked_as_deleted)) {
                    fprintf(out, "%llu %llu\r\n", i + 1, session.mails[i].size);
                }
            }
            fprintf(out, ".\r\n");
        } else if (strncasecmp(buf, "LIST ", 5) == 0 && get_message_number(buf + 5, &msgnum) == 0) {
            if (msgnum <= session.mail_count && !(session.mails[msgnum - 1].marked_as_deleted)) {
                fprintf(out, "+OK %llu %llu\r\n", msgnum, session.mails[msgnum - 1].size);
            } else {
                fprintf(out, "-ERR\r\n");
            }
        } else if (strcasecmp(buf, "UIDL") == 0) {
            fprintf(out, "+OK\r\n");
            for (unsigned long long i = 0; i < session.mail_count; i++) {
                if (!(session.mails[i].marked_as_deleted)) {
                    fprintf(out, "%llu %s\r\n", i + 1, session.mails[i].uid);
                }
            }
            fprintf(out, ".\r\n");
        } else if (strncasecmp(buf, "UIDL ", 5) == 0 && get_message_number(buf + 5, &msgnum) == 0) {
            if (msgnum <= session.mail_count && !(session.mails[msgnum - 1].marked_as_deleted)) {
                fprintf(out, "+OK %llu %s\r\n", msgnum, session.mails[msgnum - 1].uid);
            } else {
                fprintf(out, "-ERR\r\n");
            }
        } else if (strncasecmp(buf, "RETR ", 5) == 0 && get_message_number(buf + 5, &msgnum) == 0) {
            if (msgnum <= session.mail_count && !(session.mails[msgnum - 1].marked_as_deleted)) {
                FILE* mailf = fopen(session.mails[msgnum - 1].filename, "r");
                if (!mailf) {
                    fprintf(out, "-ERR cannot open message\r\n");
                    log_msg(log, log_error, "cannot open mail file %s", session.mails[msgnum - 1].filename);
                } else {
                    fprintf(out, "+OK\r\n");
                    if (send_pop3_retr_response(mailf, out) != 0) {
                        error = 1;
                        fclose(mailf);
                        log_msg(log, log_error, "cannot send mail file %s", session.mails[msgnum - 1].filename);
                        break;
                    }
                    fclose(mailf);
                    fprintf(out, ".\r\n");
                }
            } else {
                fprintf(out, "-ERR\r\n");
            }
        } else if (strncasecmp(buf, "DELE ", 5) == 0 && get_message_number(buf + 5, &msgnum) == 0) {
            if (msgnum <= session.mail_count && !(session.mails[msgnum - 1].marked_as_deleted)) {
                session.mails[msgnum - 1].marked_as_deleted = 1;
                fprintf(out, "+OK\r\n");
            } else {
                fprintf(out, "-ERR\r\n");
            }
        } else {
            fprintf(out, "-ERR command not understood\r\n");
        }
    }
    if (ferror(out)) {
        log_msg(log, log_error, "output error, session aborted");
        error = 1;
    }

    /* UPDATE state */
    if (!error) {
        unsigned long long mails_deleted = 0;
        for (unsigned long long i = 0; i < session.mail_count; i++) {
            if (session.mails[i].marked_as_deleted) {
                unlink(session.mails[i].filename);
                /* ignore errors here as there is nothing we can do */
                mails_deleted++;
            }
        }
        log_msg(log, log_info, "%llu mails deleted in update phase; session ends", mails_deleted);
    }
    end_authorized_session(&session);

    return authorization_failure_occurred ? 2 : error;
}

/* Manage the maximum number of concurrent sessions and impose a delay to
 * authentication requests after an authentication failure occured, to make
 * brute force attacks infeasible */

volatile sig_atomic_t active_sessions_count;
volatile sig_atomic_t auth_failure_occurred;
volatile time_t last_auth_failure_time;

void sigchld_action(int signum, siginfo_t* si, void* ucontext)
{
    (void)signum;   /* unused */
    (void)ucontext; /* unused */
    int wstatus;
    if (waitpid(si->si_pid, &wstatus, 0) == si->si_pid) {
        int child_exit_status = -1;
        if (WIFEXITED(wstatus))
            child_exit_status = WEXITSTATUS(wstatus);
        if (child_exit_status >= 2) {
            struct timespec tp;
            clock_gettime(CLOCK_MONOTONIC, &tp);
            last_auth_failure_time = tp.tv_sec;
            auth_failure_occurred = 1;
        }
        active_sessions_count--;
    }
}

/* Parse the command line */
int parse_command_line(int argc, char* argv[],
        int* print_version, int* print_help,
        int* inetd,
        const char** interface, int* port,
        int* log_to_syslog, const char** log_file,
        user_t** users, size_t* user_count)
{
    enum {
        mpopd_option_version,
        mpopd_option_help,
        mpopd_option_inetd,
        mpopd_option_port,
        mpopd_option_interface,
        mpopd_option_log,
        mpopd_option_auth,
        mpopd_option_maildir
    };

    struct option options[] = {
        { "version", no_argument, 0, mpopd_option_version },
        { "help", no_argument, 0, mpopd_option_help },
        { "inetd", no_argument, 0, mpopd_option_inetd },
        { "port", required_argument, 0, mpopd_option_port },
        { "interface", required_argument, 0, mpopd_option_interface },
        { "log", required_argument, 0, mpopd_option_log },
        { "auth", required_argument, 0, mpopd_option_auth },
        { "maildir", required_argument, 0, mpopd_option_maildir },
        { 0, 0, 0, 0 }
    };

    for (;;) {
        int option_index = -1;
        int c = getopt_long(argc, argv, "", options, &option_index);
        if (c == -1)
            break;
        if (optarg && optarg[0] == '\0') {
            fprintf(stderr, "%s: option '--%s' requires non-empty argument\n", argv[0],
                    options[option_index].name);
            return 1;
        }
        switch (c) {
        case mpopd_option_version:
            *print_version = 1;
            break;
        case mpopd_option_help:
            *print_help = 1;
            break;
        case mpopd_option_inetd:
            *inetd = 1;
            break;
        case mpopd_option_port:
            *port = atoi(optarg);
            break;
        case mpopd_option_interface:
            *interface = optarg;
            break;
        case mpopd_option_log:
            if (strcmp(optarg, "none") == 0) {
                *log_to_syslog = 0;
                *log_file = NULL;
            } else if (strcmp(optarg, "syslog") == 0) {
                *log_to_syslog = 1;
                *log_file = NULL;
            } else {
                *log_to_syslog = 0;
                *log_file = optarg;
            }
            break;
        case mpopd_option_maildir:
            if (*user_count == 0) {
                fprintf(stderr, "%s: option '--%s' requires preceding option '--auth'\n",
                        argv[0], options[option_index].name);
                return 1;
            }
            (*users)[*user_count - 1].maildir = xstrdup(optarg);
            break;
        case mpopd_option_auth:
            {
                char* comma = strchr(optarg, ',');
                char* tmp_user = NULL;
                char* tmp_password = NULL;
                if (!comma) {
                    tmp_user = xstrdup(optarg);
                    tmp_password = password_get("localhost", tmp_user, password_service_pop3, 0, 0);
                    if (!tmp_password) {
                        fprintf(stderr, "%s: cannot get password for (localhost, pop3, %s)\n",
                                argv[0], tmp_user);
                        free(tmp_user);
                        return 1;
                    }
                } else {
                    tmp_user = xstrndup(optarg, comma - optarg);
                    char* errstr = NULL;
                    if (password_eval(comma + 1, &tmp_password, &errstr) != 0) {
                        fprintf(stderr, "%s: cannot get password: %s\n", argv[0], errstr);
                        free(tmp_user);
                        free(errstr);
                        return 1;
                    }
                }
                (*user_count)++;
                *users = xrealloc(*users, *user_count * sizeof(user_t));
                (*users)[*user_count - 1].user = tmp_user;
                (*users)[*user_count - 1].password = tmp_password;
                (*users)[*user_count - 1].maildir = NULL;
            }
            break;
        default:
            return 1;
            break;
        }
    }
    if (argc - optind > 0) {
        fprintf(stderr, "%s: too many arguments\n", argv[0]);
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[])
{
    /* Exit status values according to LSB init script recommendations */
    const int exit_ok = 0;
    const int exit_not_running = 3;

    /* Configuration */
    int print_version = 0;
    int print_help = 0;
    int inetd = 0;
    const char* interface = DEFAULT_INTERFACE;
    int port = DEFAULT_PORT;
    int log_to_syslog = 0;
    const char* log_file = NULL;
    user_t* users = NULL;
    size_t user_count = 0;
    int ret = exit_ok;

    /* Command line */
    if (parse_command_line(argc, argv,
                &print_version, &print_help,
                &inetd, &interface, &port,
                &log_to_syslog, &log_file,
                &users, &user_count) != 0) {
        ret = exit_not_running;
    } else if (print_version) {
        printf("mpopd version %s\n", VERSION);
        printf("Copyright (C) 2021 Martin Lambers.\n"
                "This is free software.  You may redistribute copies of it under the terms of\n"
                "the GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\n"
                "There is NO WARRANTY, to the extent permitted by law.\n");
    } else if (print_help) {
        printf("Usage: mpopd [option...]\n");
        printf("Options:\n");
        printf("  --version       print version\n");
        printf("  --help          print help\n");
        printf("  --inetd         start single SMTP session on stdin/stdout\n");
        printf("  --interface=ip  listen on ip instead of %s\n", DEFAULT_INTERFACE);
        printf("  --port=number   listen on port number instead of %d\n", DEFAULT_PORT);
        printf("  --log=none|syslog|FILE  do not log anything (default)\n");
        printf("                  or log to syslog or log to the given file\n");
        printf("  --auth=user[,passwordeval] require authentication with this user name;\n");
        printf("                  the password will be retrieved from the given\n");
        printf("                  passwordeval command or, if none is given, from\n");
        printf("                  the key ring or, if that fails, from a prompt.\n");
        printf("  --maildir=dir   use this maildir as mailbox\n");
        printf("Each pair of --auth and --maildir options defines one POP3 mailbox.\n");
        printf("At least one such pair must be given.\n");
    } else if (user_count == 0) {
        fprintf(stderr, "%s: missing --auth and --maildir option\n", argv[0]);
        ret = exit_not_running;
    } else {
        for (size_t i = 0; i < user_count; i++) {
            if (!users[i].maildir) {
                fprintf(stderr, "%s: missing --maildir option for user %s\n", argv[0], users[i].user);
                ret = exit_not_running;
            }
        }
    }
    if (ret != exit_ok) {
        for (size_t i = 0; i < user_count; i++) {
            free(users[i].user);
            free(users[i].password);
            free(users[i].maildir);
        }
        free(users);
        return ret;
    }

    /* Do it */
    if (inetd) {
        /* We are no daemon, so we can just signal error with exit status 1 and success with 0 */
        log_t log;
        log_open(log_to_syslog, log_file, &log);
        int impose_auth_delay = 1; /* since we cannot keep track of auth failures in inetd mode */
        ret = mpopd_session(&log, stdin, stdout, users, user_count, impose_auth_delay);
        ret = (ret == 0 ? 0 : 1);
        log_close(&log);
    } else {
        int ipv6;
        struct sockaddr_in6 sa6;
        struct sockaddr_in sa4;
        int listen_fd;
        int on = 1;

        /* Set interface */
        memset(&sa6, 0, sizeof(sa6));
        if (inet_pton(AF_INET6, interface, &sa6.sin6_addr) != 0) {
            ipv6 = 1;
            sa6.sin6_family = AF_INET6;
            sa6.sin6_port = htons(port);
        } else {
            memset(&sa4, 0, sizeof(sa4));
            if (inet_pton(AF_INET, interface, &sa4.sin_addr) != 0) {
                ipv6 = 0;
                sa4.sin_family = AF_INET;
                sa4.sin_port = htons(port);
            } else {
                fprintf(stderr, "%s: invalid interface\n", argv[0]);
                ret = exit_not_running;
                goto exit;
            }
        }

        /* Create and set up listening socket */
        listen_fd = socket(ipv6 ? PF_INET6 : PF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
            fprintf(stderr, "%s: cannot create socket: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
            fprintf(stderr, "%s: cannot set socket option: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (bind(listen_fd,
                    ipv6 ? (struct sockaddr*)&sa6 : (struct sockaddr*)&sa4,
                    ipv6 ? sizeof(sa6) : sizeof(sa4)) < 0) {
            fprintf(stderr, "%s: cannot bind to %s:%d: %s\n", argv[0], interface, port, strerror(errno));
            ret = exit_not_running;
            goto exit;
        }
        if (listen(listen_fd, 128) < 0) {
            fprintf(stderr, "%s: cannot listen on socket: %s\n", argv[0], strerror(errno));
            ret = exit_not_running;
            goto exit;
        }

        /* Set up signal handling, in part conforming to freedesktop.org modern daemon requirements */
        signal(SIGHUP, SIG_IGN); /* Reloading configuration does not make sense for us */
        signal(SIGTERM, SIG_DFL); /* We can be terminated as long as there is no running session */

        /* Set SIGCHLD signal handler to manage maximum number of active sessions and impose
         * authentication delays in case of authentication failures (to make brute force attacks unfeasible) */
        active_sessions_count = 0;
        auth_failure_occurred = 0;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO | SA_RESTART; /* SA_RESTART: restart accept() after SIGCHLD */
        sa.sa_sigaction = sigchld_action;
        sigaction(SIGCHLD, &sa, NULL); /* cannot fail */

        /* Accept connection */
        for (;;) {
            while (active_sessions_count >= MAX_ACTIVE_SESSIONS) {
                sleep(1);
            }
            socklen_t client_len = ipv6 ? sizeof(sa6) : sizeof(sa4);
            int conn_fd = accept(listen_fd, ipv6 ? (struct sockaddr*)&sa6 : (struct sockaddr*)&sa4, &client_len);
            if (conn_fd < 0) {
                fprintf(stderr, "%s: cannot accept connection: %s\n", argv[0], strerror(errno));
                ret = exit_not_running;
                break;
            }
            char client_ip_str[INET6_ADDRSTRLEN];
            int client_port;
            if (ipv6) {
                inet_ntop(AF_INET6, &sa6.sin6_addr, client_ip_str, sizeof(client_ip_str));
                client_port = ntohs(sa6.sin6_port);
            } else {
                inet_ntop(AF_INET, &sa4.sin_addr, client_ip_str, sizeof(client_ip_str));
                client_port = ntohs(sa4.sin_port);
            }
            pid_t pid = fork();
            if (pid == 0) {
                /* Child process */
                int impose_auth_delay = 0;
                if (auth_failure_occurred) {
                    struct timespec tp;
                    clock_gettime(CLOCK_MONOTONIC, &tp);
                    int seconds_since_last_auth_failure = tp.tv_sec - last_auth_failure_time;
                    if (seconds_since_last_auth_failure <= AUTH_DELAY_EXPIRATION_SECONDS)
                        impose_auth_delay = 1;
                }
                signal(SIGTERM, SIG_IGN); /* A running session should not be terminated */
                log_t log;
                log_open(log_to_syslog, log_file, &log);
                log_msg(&log, log_info, "connection from %s port %d, active sessions %d (max %d), auth_delay=%s",
                        client_ip_str, client_port,
                        active_sessions_count + 1, MAX_ACTIVE_SESSIONS, impose_auth_delay ? "yes" : "no");
                FILE* conn = fdopen(conn_fd, "rb+");
                int ret = mpopd_session(&log, conn, conn, users, user_count, impose_auth_delay);
                fclose(conn);
                log_msg(&log, log_info, "connection closed");
                log_close(&log);
                exit(ret);
            } else {
                /* Parent process */
                close(conn_fd);
                if (pid > 0) {
                    active_sessions_count++;
                } else {
                    fprintf(stderr, "%s: fork failed: %s\n", argv[0], strerror(errno));
                    ret = exit_not_running;
                    break;
                }
            }
        }
    }

exit:
    for (size_t i = 0; i < user_count; i++) {
        free(users[i].user);
        free(users[i].password);
        free(users[i].maildir);
    }
    free(users);
    return ret;
}

/* Die if memory allocation fails. Note that we only use xalloc() etc
 * during startup; one mpopd is running, out of memory conditions are
 * handled gracefully. */

void xalloc_die(void)
{
    fputs(strerror(ENOMEM), stderr);
    fputc('\n', stderr);
    exit(3);
}
