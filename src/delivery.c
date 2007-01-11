/*
 * delivery.c
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2005, 2006, 2007
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
#include <string.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sysexits.h>
#if HAVE_SIGACTION
# include <signal.h>
#endif
#ifdef W32_NATIVE
# include <winsock2.h>
# include <io.h>
# include <direct.h>
# include <sys/timeb.h>
# define WIFEXITED(s) (1)
# define WEXITSTATUS(s) (s)
#else
# include <sys/wait.h>
#endif

#include "gettext.h"
#include "xalloc.h"
#include "xvasprintf.h"

#include "tools.h"
#include "delivery.h"


/*******************************************************************************
 *
 *  Misc. helper functions
 *
 ******************************************************************************/


/* 
 * exitcode_to_string()
 *
 * Return the name of a sysexits.h exitcode.
 * If the exitcode is not known, NULL is returned.
 */

const char *exitcode_to_string(int exitcode)
{
    switch (exitcode)
    {
	case EX_OK:
	    return _("EX_OK: no error");

	case EX_USAGE:
	    return _("EX_USAGE: command line usage error");
	    
	case EX_DATAERR:
	    return _("EX_DATAERR: data format error");

	case EX_NOINPUT:
	    return _("EX_NOINPUT: no input");

	case EX_NOUSER:
	    return _("EX_NOUSER: user unknown");

	case EX_NOHOST:
	    return _("EX_NOHOST: host name unknown");

	case EX_UNAVAILABLE:
	    return _("EX_UNAVAILABLE: service unavailable");

	case EX_SOFTWARE:
	    return _("EX_SOFTWARE: internal software error");

	case EX_OSERR:
	    return _("EX_OSERR: system error");

	case EX_OSFILE:
	    return _("EX_OSFILE: system file missing");
	    
	case EX_CANTCREAT:
	    return _("EX_CANTCREAT: cannot create output file");
	    
	case EX_IOERR:
	    return _("EX_IOERR: input/output error");

	case EX_TEMPFAIL:
	    return _("EX_TEMPFAIL: temporary failure");
	    
	case EX_PROTOCOL:
	    return _("EX_PROTOCOL: remote error in protocol");

	case EX_NOPERM:
	    return _("EX_NOPERM: permission denied");

	case EX_CONFIG:
	    return _("EX_CONFIG: configuration error");

	default:
	    return NULL;
    }
}


/*******************************************************************************
 *
 *  The MDA method
 *
 ******************************************************************************/

#if HAVE_SIGACTION
static volatile sig_atomic_t mda_caused_sigpipe;
static struct sigaction mda_old_sigpipe_handler;
static void mda_sigpipe_handler(int signum UNUSED)
{   
    mda_caused_sigpipe = 1;
}
#endif

int delivery_method_mda_open(delivery_method_t *dm, const char *from, long size,
	char **errstr)
{
    int e;
    char *cmd;
    char *sizestr;
    
    cmd = xstrdup((char *)(dm->data));
    if (dm->want_from_addr)
    {
	cmd = string_replace(cmd, "%F", from);
    }
    if (dm->want_size)
    {
	sizestr = xasprintf("%ld", size);
	cmd = string_replace(cmd, "%S", sizestr);
	free(sizestr);
    }
    if (fflush(stdout) != 0 || fflush(stderr) != 0
	    || !(dm->pipe = popen(cmd, "w")))
    {
	*errstr = xasprintf(_("cannot execute %s"), cmd);
	e = DELIVERY_EUNKNOWN;
    }
    else
    {
	e = DELIVERY_EOK;
    }
    free(cmd);
    return e;
}

int delivery_method_mda_close(delivery_method_t *dm, char **errstr)
{
    int status;
    const char *tmp;
    
    status = pclose(dm->pipe);
#if HAVE_SIGACTION
    if (mda_caused_sigpipe)
    {
	*errstr = xasprintf(_("%s did not read mail data"), (char *)(dm->data));
	return DELIVERY_EUNKNOWN;
    }
    else
#endif
    if (status == -1 || !WIFEXITED(status))
    {
	*errstr = xasprintf(_("%s failed to execute"), (char *)(dm->data));
	return DELIVERY_EUNKNOWN;
    }
    else
    {
	status = WEXITSTATUS(status);
	if (status != 0)
	{
	    if ((tmp = exitcode_to_string(status)))
    	    {
		*errstr = xasprintf(_("%s returned exit status %d (%s)"),
			(char *)(dm->data), status, tmp);
	    }
	    else
	    {
		*errstr = xasprintf(_("%s returned exit status %d"), 
			(char *)(dm->data), status);
	    }
	    return DELIVERY_EUNKNOWN;
	}
	else
	{
	    return DELIVERY_EOK;
	}
    }
}

int delivery_method_mda_init(delivery_method_t *dm, void *data, 
	char **errstr UNUSED)
{
#if HAVE_SIGACTION
    struct sigaction signal_handler;
#endif

    dm->data = data;
    dm->need_from_quoting = 0;
    dm->want_from_addr = (strstr((char *)data, "%F") != NULL);
    dm->want_size = 0;
    dm->open = delivery_method_mda_open;
    dm->close = delivery_method_mda_close;
#if HAVE_SIGACTION
    mda_caused_sigpipe = 0;
    signal_handler.sa_handler = mda_sigpipe_handler;
    sigemptyset(&signal_handler.sa_mask);
    signal_handler.sa_flags = 0;
    (void)sigaction(SIGPIPE, &signal_handler, &mda_old_sigpipe_handler);
#endif
    return DELIVERY_EOK;
}

int delivery_method_mda_deinit(delivery_method_t *dm UNUSED, 
	char **errstr UNUSED)
{
#if HAVE_SIGACTION
    (void)sigaction(SIGPIPE, &mda_old_sigpipe_handler, NULL);
#endif
    return DELIVERY_EOK;
}


/*******************************************************************************
 *
 *  The filter method
 *
 ******************************************************************************/

/* This method reuses the MDA method's open, init, and deinit functions. */

int delivery_method_filter_close(delivery_method_t *dm, char **errstr)
{
    int status;
    const char *tmp;
    
    status = pclose(dm->pipe);
#if HAVE_SIGACTION
    if (mda_caused_sigpipe)
    {
	*errstr = xasprintf(_("%s did not read mail data"), (char *)(dm->data));
	return DELIVERY_EUNKNOWN;
    }
    else
#endif
    if (status == -1 || !WIFEXITED(status))
    {
	*errstr = xasprintf(_("%s failed to execute"), (char *)(dm->data));
	return 3;
    }
    else
    {
	status = WEXITSTATUS(status);
	if (status != 0 && status != 1 && status != 2)
	{
	    if ((tmp = exitcode_to_string(status)))
    	    {
		*errstr = xasprintf(_("%s returned exit status %d (%s)"), 
			(char *)(dm->data), status, tmp);
	    }
	    else
	    {
		*errstr = xasprintf(_("%s returned exit status %d"), 
			(char *)(dm->data), status);
	    }
	    return 3;
	}
	else
	{
	    return status;
	}
    }
}

int delivery_method_filter_init(delivery_method_t *dm, void *data, 
	char **errstr)
{
    int e;
    
    if ((e = delivery_method_mda_init(dm, data, errstr)) != DELIVERY_EOK)
    {
	return e;
    }
    dm->want_size = (strstr((char *)data, "%S") != NULL);
    dm->close = delivery_method_filter_close;
    return DELIVERY_EOK;
}

int delivery_method_filter_deinit(delivery_method_t *dm, char **errstr)
{
    return delivery_method_mda_deinit(dm, errstr);
}


/*******************************************************************************
 *
 *  The maildir method.
 *  
 *  You can use it on DJGPP systems, but you need long file name support.
 *
 ******************************************************************************/

/* W32 does not have gettimeofday(). */
#ifdef W32_NATIVE
int gettimeofday(struct timeval *tv, void *tz UNUSED)
{
    struct _timeb timebuf;
    _ftime(&timebuf);
    tv->tv_sec = timebuf.time;
    tv->tv_usec = timebuf.millitm * 1000;
    return 0;
}
#endif

/* This number is unique for the current process. It is used to create unique
 * maildir filenames. */
static unsigned long maildir_sequence_number = 0;

typedef struct
{
    char *maildir;
    char *filename;
    char *hostname;
} maildir_data_t;

int delivery_method_maildir_open(delivery_method_t *dm, const char *from UNUSED,
	long size UNUSED, char **errstr)
{
    maildir_data_t *maildir_data;
    char *filename;
    struct timeval tv;
    int fd;
    

    maildir_data = dm->data;
    if (gettimeofday(&tv, NULL) < 0)
    {
	*errstr = xasprintf(_("cannot get system time: %s"), strerror(errno));
	return DELIVERY_EUNKNOWN;
    }
    /* See http://cr.yp.to/proto/maildir.html for a description of file name
     * generation. */
    filename = xasprintf("tmp%c%lu.M%06luP%ldQ%lu.%s", PATH_SEP,
		(unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec,
		(long)getpid(), ++maildir_sequence_number, 
		maildir_data->hostname);
    /* Instead of waiting for stat() to return ENOENT, we open() the file with
     * O_CREAT | O_EXCL. There is no point in trying again after some time,
     * because the filename is intended to be unique. If it is not, we should
     * fix the filename generation instead. */
    if ((fd = open(filename, O_WRONLY | O_CREAT | O_EXCL, 
		    S_IRUSR | S_IWUSR)) < 0)
    {
	*errstr = xasprintf(_("cannot create %s%c%s: %s"), 
		maildir_data->maildir, PATH_SEP, filename, strerror(errno));
	free(filename);
	return DELIVERY_EIO;
    }
    maildir_data->filename = filename;
    if (!(dm->pipe = fdopen(fd, "w")))
    {
	*errstr = xasprintf(_("cannot open %s%c%s: %s"), maildir_data->maildir,
		PATH_SEP, maildir_data->filename, strerror(errno));
	return DELIVERY_EIO;
    }
    return DELIVERY_EOK;
}

int delivery_method_maildir_close(delivery_method_t *dm, char **errstr)
{
    maildir_data_t *maildir_data;
    char *newfilename;
    
    maildir_data = dm->data;
#ifndef W32_NATIVE
    /* FIXME: Do a sync on Win32, too. If you know how, please send a mail. */
    if (fsync(fileno(dm->pipe)) != 0)
    {
	*errstr = xasprintf(_("cannot sync %s%c%s: %s"), maildir_data->maildir, 
		PATH_SEP, maildir_data->filename, strerror(errno));
	return DELIVERY_EIO;
    }
#endif /* ! W32_NATIVE */
    if (fclose(dm->pipe) != 0)
    {
	*errstr = xasprintf(_("cannot close %s%c%s: %s"), maildir_data->maildir,
		PATH_SEP, maildir_data->filename, strerror(errno));
	return DELIVERY_EIO;
    }
    newfilename = xstrdup(maildir_data->filename);
    strncpy(newfilename, "new", 3);
#ifndef W32_NATIVE
    if (link(maildir_data->filename, newfilename) != 0)
    {
	*errstr = xasprintf(_("%s: cannot link %s to %s: %s"), 
		maildir_data->maildir, maildir_data->filename, newfilename, 
		strerror(errno));
	free(newfilename);
	return DELIVERY_EIO;
    }
    (void)unlink(maildir_data->filename);
#else /* W32_NATIVE */
    if (rename(maildir_data->filename, newfilename) != 0)
    {
	*errstr = xasprintf(_("%s: cannot move %s to %s: %s"), 
		maildir_data->maildir, maildir_data->filename, newfilename, 
		strerror(errno));
	free(newfilename);
	return DELIVERY_EIO;
    }
#endif /* ! W32_NATIVE */	 
    free(newfilename);
    free(maildir_data->filename);
    maildir_data->filename = NULL;

    return DELIVERY_EOK;
}

int delivery_method_maildir_init(delivery_method_t *dm, void *data, 
	char **errstr)
{
    maildir_data_t *maildir_data;
    char hostname[256];
    
    maildir_data = xmalloc(sizeof(maildir_data_t));
    maildir_data->maildir = xstrdup((char *)data);
    maildir_data->filename = NULL;
    if (gethostname(hostname, 256) != 0)
    {
	/* Should never happen on any sane system */
	strcpy(hostname, "unknown");
    }
    else
    {
	/* Make sure the hostname is NUL-terminated. */
	hostname[255] = '\0';
    }
    maildir_data->hostname = xstrdup(hostname);
    /* replace invalid characters as described in
     * http://cr.yp.to/proto/maildir.html */
#ifndef W32_NATIVE
    maildir_data->hostname = string_replace(maildir_data->hostname, "/", 
	    "\\057");
    maildir_data->hostname = string_replace(maildir_data->hostname, ":", 
	    "\\072");
#else /* W32_NATIVE */
    maildir_data->hostname = string_replace(maildir_data->hostname, "/", 
	    "_057_");
    maildir_data->hostname = string_replace(maildir_data->hostname, ":", 
	    "_072_");
    maildir_data->hostname = string_replace(maildir_data->hostname, "\\", 
	    "_134_");
#endif
    dm->data = maildir_data;
    dm->need_from_quoting = 0;
    dm->want_from_addr = 0;
    dm->want_size = 0;
    dm->open = delivery_method_maildir_open;
    dm->close = delivery_method_maildir_close;
    if (chdir(maildir_data->maildir) != 0)
    {
	*errstr = xasprintf(_("cannot change to %s: %s"), maildir_data->maildir,
		strerror(errno));
	return DELIVERY_EUNKNOWN;
    }
#ifndef W32_NATIVE
    (void)umask(077);
#endif

    return DELIVERY_EOK;
}

int delivery_method_maildir_deinit(delivery_method_t *dm, char **errstr UNUSED)
{
    maildir_data_t *maildir_data = dm->data;
    free(maildir_data->maildir);
    free(maildir_data->filename);
    free(maildir_data->hostname);
    free(maildir_data);
    return DELIVERY_EOK;
}


/*******************************************************************************
 *
 *  The mbox method
 *
 ******************************************************************************/

int delivery_method_mbox_open(delivery_method_t *dm, const char *from, 
	long size UNUSED, char **errstr)
{
    time_t t;

    if ((t = time(NULL)) < 0)
    {
	*errstr = xasprintf(_("cannot get system time: %s"), strerror(errno));
	return DELIVERY_EUNKNOWN;
    }
    /* Write the From_ line. */
    if (fprintf(dm->pipe, "From %s %s", from, asctime(gmtime(&t))) < 0)
    {
	*errstr = xasprintf(_("%s: output error"), (char *)(dm->data));
	return DELIVERY_EIO;
    }
    
    return DELIVERY_EOK;
}

int delivery_method_mbox_close(delivery_method_t *dm, char **errstr)
{
    if (fputc('\n', dm->pipe) == EOF)
    {
	*errstr = xasprintf(_("%s: output error"), (char *)(dm->data));
	return DELIVERY_EIO;
    }
#ifndef W32_NATIVE
    /* FIXME: Do a sync on Win32, too. If you know how, please send a mail. */
    if (fsync(fileno(dm->pipe)) != 0)
    {
	/* Ignore the condition (errno == EINVAL): fsync() is not possible with
	 * this file; the user probably used /dev/null or some other special
	 * file as an mbox. */
	if (errno != EINVAL)
	{
	    *errstr = xasprintf(_("cannot sync %s: %s"), (char *)(dm->data), 
	    	    strerror(errno));
	    return DELIVERY_EIO;
	}
    }
#endif /* ! W32_NATIVE */
    if (ferror(dm->pipe))
    {
	*errstr = xasprintf(_("%s: output error"), (char *)(dm->data));
	return DELIVERY_EIO;
    }
    return DELIVERY_EOK;
}

int delivery_method_mbox_init(delivery_method_t *dm, void *data, char **errstr)
{
    const int lock_timeout = 10;
    int e;

    dm->data = data;
    dm->need_from_quoting = 1;
    dm->want_from_addr = 1;
    dm->want_size = 0;
    dm->open = delivery_method_mbox_open;
    dm->close = delivery_method_mbox_close;
#ifndef W32_NATIVE
    (void)umask(077);
#endif
    if (!(dm->pipe = fopen((char *)data, "a")))
    {
	*errstr = xasprintf(_("cannot open %s: %s"), (char *)data, 
		strerror(errno));
	return DELIVERY_EUNKNOWN;
    }
    if ((e = lock_file(dm->pipe, TOOLS_LOCK_WRITE, lock_timeout)) != 0)
    {
	if (e == 1)
	{
	    *errstr = xasprintf(_("cannot lock %s (tried for %d seconds): %s"), 
		    (char *)data, lock_timeout, strerror(errno));
	}
	else
	{
	    *errstr = xasprintf(_("cannot lock %s: %s"), 
		    (char *)data, strerror(errno));
	}
	fclose(dm->pipe);
	return DELIVERY_EUNKNOWN;
    }
    
    return DELIVERY_EOK;
}

int delivery_method_mbox_deinit(delivery_method_t *dm, char **errstr)
{
    /* unlocking is done automatically with fclose() */
    if (fclose(dm->pipe) != 0)
    {
	*errstr = xasprintf(_("cannot close %s: %s"), (char *)(dm->data),
		strerror(errno));
	return DELIVERY_EIO;
    }
    return DELIVERY_EOK;
}


/*******************************************************************************
 *
 *  Common functions
 *
 ******************************************************************************/


/*
 * delivery_method_new()
 *
 * see delivery.h
 */

delivery_method_t *delivery_method_new(int method, void *data, char **errstr)
{
    int e = 0;
    delivery_method_t *dm;
    
    dm = xmalloc(sizeof(delivery_method_t));
    dm->method = method;
    switch (method)
    {
	case DELIVERY_METHOD_MDA:
	    e = delivery_method_mda_init(dm, data, errstr);
	    break;

	case DELIVERY_METHOD_MAILDIR:
	    e = delivery_method_maildir_init(dm, data, errstr);
	    break;

	case DELIVERY_METHOD_MBOX:
	    e = delivery_method_mbox_init(dm, data, errstr);
	    break;

	case DELIVERY_METHOD_FILTER:
	    e = delivery_method_filter_init(dm, data, errstr);
	    break;
    }
    if (e != DELIVERY_EOK)
    {
	free(dm);
	return NULL;
    }
    else
    {
	return dm;
    }
}


/*
 * delivery_method_free()
 *
 * see delivery.h
 */

int delivery_method_free(delivery_method_t *dm, char **errstr)
{
    int e = 0;
    
    switch (dm->method)
    {
	case DELIVERY_METHOD_MDA:
	    e = delivery_method_mda_deinit(dm, errstr);
	    break;

	case DELIVERY_METHOD_MAILDIR:
	    e = delivery_method_maildir_deinit(dm, errstr);
	    break;

	case DELIVERY_METHOD_MBOX:
	    e = delivery_method_mbox_deinit(dm, errstr);
	    break;

	case DELIVERY_METHOD_FILTER:
	    e = delivery_method_filter_deinit(dm, errstr);
	    break;
    }
    free(dm);
    return e;
}
