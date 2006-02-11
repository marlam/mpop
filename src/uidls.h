/*
 * uidls.h
 *
 * This file is part of mpop, a POP3 client.
 *
 * Copyright (C) 2005, 2006
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

#ifndef UIDLS_H
#define UIDLS_H

#include "list.h"


/*
 * If a function with an 'errstr' argument returns a value != UIDLS_EOK,
 * '*errstr' either points to an allocates string containing an error 
 * description or is NULL.
 * If such a function returns UIDLS_EOK, 'errstr' will not be changed.
 */
#define UIDLS_EOK	0	/* no error */
#define UIDLS_EIO	1	/* input/output error */
#define UIDLS_EFORMAT	2	/* file has invalid format */

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
 * '*uidl_list', which is newly created.
 * If the file cannot be opened, it is assumed that it does not exist, and this
 * is not considered an error! The list will simply be empty in this case.
 * The UIDs in each uidl in the list will be in ascending order.
 * Used error codes: UIDLS_EIO, UIDLS_EFORMAT
 */
int uidls_read(const char *filename, list_t **uidl_list, char **errstr);

/*
 * uidls_write()
 *
 * Writes the UIDLs from the list 'uidl_list' into a file.
 * Used error codes: UIDLS_EIO
 */
int uidls_write(const char *filename, list_t *uidl_list, char **errstr);

#endif
