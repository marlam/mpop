/*
 * delivery.h
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2005, 2006, 2007, 2009
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

#ifndef DELIVERY_H
#define DELIVERY_H

#include <stdio.h>


/*
 * Explanation of the available delivery methods:
 *
 * DELIVERY_METHOD_MDA:
 *   This delivery method starts a mail delivery agent via popen() for each
 *   mail. The 'data' argument is the command line of the MDA. It will be
 *   interpreted by the shell, after every occurence of %F was replaced with the
 *   envelope from address of the current mail.
 *
 * DELIVERY_METHOD_MAILDIR:
 *   This delivery method delivers each mail to a maildir directory. The 'data'
 *   argument is the name of that directory. See also
 *   http://www.qmail.org/qmail-manual-html/man5/maildir.html
 *
 * DELIVERY_METHOD_MBOX:
 *   This delivery method writes each mail to the same mbox file, which is
 *   locked using fcntl(2) locks. The 'data' argument is the file name of the
 *   mbox file. The format of the file will be the mboxrd variant as described
 *   in http://www.qmail.org/qmail-manual-html/man5/mbox.html .
 *
 * DELIVERY_METHOD_EXCHANGE:
 *   This method delivers each mail to a MS Exchange pickup directory. See also
 *   http://technet.microsoft.com/en-us/library/bb124230.aspx
 *
 * DELIVERY_METHOD_FILTER:
 *   This method is special. It behaves like DELIVERY_METHOD_MDA, with to
 *   exceptions:
 *   1. In addition to %F-replacement, every occurence of %S in the data
 *      argument will be replaced with the size of the current mail as reporte
 *      by the POP3 server.
 *   2. The close function does not return a DELIVERY_* exit code, but one of
 *      the following:
 *      0: filter command executed successfully and returned 0
 *      1: filter command executed successfully and returned 1
 *      2: filter command executed successfully and returned 2
 *      3: filter command could not be executed or it returned an exit code
 *         other than 0, 1, or 2
 */


/*
 * If a function with an 'errstr' argument returns a value != DELIVERY_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns DELIVERY_EOK, 'errstr' will not be changed.
 */
#define DELIVERY_EOK            0       /* no error */
#define DELIVERY_EIO            1       /* input/output error */
#define DELIVERY_EUNKNOWN       2       /* unknown error */

/* These delivery methods are supported: */
#define DELIVERY_METHOD_MDA             0 /* pipe to a mail delivery agent */
#define DELIVERY_METHOD_MAILDIR         1 /* write to a file in mbox format */
#define DELIVERY_METHOD_MBOX            2 /* write to a file in mbox format */
#define DELIVERY_METHOD_EXCHANGE        3 /* delivery into MS Exchange pickup
                                             directory */
#define DELIVERY_METHOD_FILTER          4 /* a special case of METHOD_MDA
                                             that is used for filtering. */

typedef struct _delivery_method
{
    /* One of the DELIVERY_METHOD_* constants: */
    int method;
    /* Arbitrary data that a method can use: */
    void *data;

    /*
     * The following members are used by the caller.
     */

    /* The pipe that the data is written to: */
    FILE *pipe;
    /* Whether this method wants the mail's envelope from address: */
    int want_from_addr;
    /* Whether this method wants the mail's size: */
    int want_size;
    /* Whether this method needs From quoting: */
    int need_from_quoting;
    /* Whether this method needs CRLF line endings: */
    int need_crlf;
    /* Open 'pipe' for a new mail. If 'want_from_addr' is set, then 'from' must
     * point to a valid mail address. It is important that this address only
     * contains characters that are valid in a mail address, since it might be
     * passed to a shell. If 'want_from_addr' is not set, then 'from' must be
     * NULL. If 'want_size' is set, then 'size' should contain the size of the
     * mail as reported by the POP3 server. If 'want_size' is not set, 'size' is
     * ignored. */
    int (*open)(struct _delivery_method *dm, const char *from, long long size,
            char **errstr);
    /* Close 'pipe' after a mail was written to 'pipe': */
    int (*close)(struct _delivery_method *dm, char **errstr);
} delivery_method_t;


/*
 * delivery_method_new()
 *
 * Prepare a delivery method for usage.
 * The 'data' argument may point to arbitrary data that the method may need; see
 * the explanation of the method for a description.
 * This method returns NULL on failure.
 */
delivery_method_t *delivery_method_new(int method, void *data, char **errstr);

/*
 * delivery_method_free()
 *
 * End the usage of the given method and free its resources.
 * Used error codes: DELIVERY_EUNKNOWN
 */
int delivery_method_free(delivery_method_t *dm, char **errstr);

#endif
