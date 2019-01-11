/*
 * uidls.h
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2005, 2006, 2007, 2008, 2019
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

#ifndef UIDLS_H
#define UIDLS_H

#include "list.h"


/*
 * If a function with an 'errstr' argument returns a value != UIDLS_EOK,
 * '*errstr' either points to an allocates string containing an error
 * description or is NULL.
 * If such a function returns UIDLS_EOK, 'errstr' will not be changed.
 */
#define UIDLS_EOK       0       /* no error */
#define UIDLS_EIO       1       /* input/output error */
#define UIDLS_EFORMAT   2       /* file has invalid format */

/* An UIDL is a list of n UIDs for one user/hostname pair. */
typedef struct
{
    char *hostname;
    char *user;
    long n;
    char **uidv;
} uidl_t;

/*
 * uidl_new()
 *
 * Creates a new uidl_t with the given hostname and user.
 */
uidl_t *uidl_new(const char *hostname, const char *user);

/*
 * uidl_free()
 *
 * Frees an uidl_t.
 */
void uidl_free(void *u);

/*
 * uidls_uidcmp()
 *
 * Compares to UID strings. Return value is like strcmp().
 * This function can be used as an argument to qsort()
 * and bsearch().
 */
int uidls_uidcmp(const void *a, const void *b);

/*
 * uidl_find()
 *
 * Find an UID list in a list of UID lists.
 * Returns NULL if not found.
 */
uidl_t *find_uidl(list_t *uidl_list, const char *hostname, const char *user);

/*
 * uidls_read()
 *
 * Reads the UIDLs for different user/hostname pairs from a file into the list
 * 'uidl_list', which is newly created.
 * The FILE pointer is stored in 'uidls_file'. This pointer must be used in a
 * suqsequent call to uidls_write(), and for nothing else (except that it should
 * be closed when no call to uidls_write() follows).
 * A nonexistant file will be treated as an empty file.
 * The UIDs in each uidl in the list will be in ascending order.
 * Used error codes: UIDLS_EIO, UIDLS_EFORMAT
 */
int uidls_read(const char *filename, FILE **uidls_file, list_t **uidl_list,
        char **errstr);

/*
 * uidls_write()
 *
 * Writes the UIDLs from the list 'uidl_list' into a UIDLS file. Both 'filename'
 * and 'uidls_file' must be the same as in the call to uidls_read(). This
 * function will close 'uidls_file'. 'errstr' may be NULL, in which case no
 * error message will be returned.
 * Used error codes: UIDLS_EIO
 */
int uidls_write(const char *filename, FILE *uidls_file, list_t *uidl_list,
        char **errstr);

/*
 * uidls_exitcode()
 *
 * Translate UIDLS_* error code to an error code from sysexits.h
 */
int uidls_exitcode(int uidls_error_code);

#endif
