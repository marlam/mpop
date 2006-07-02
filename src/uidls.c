/*
 * uidls.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
extern int errno;
#include <unistd.h>

#include "gettext.h"
#include "xalloc.h"
#include "xvasprintf.h"

#include "uidls.h"
#include "list.h"
#include "tools.h"


/* The timeout for locking the UIDLs file, in seconds. */
#define UIDLS_LOCK_TIMEOUT	10

/* A line from an UIDLs file must fit into a buffer of this size: */
#define UIDLS_LINEBUFSIZE	501


/*
 * uidl_new()
 *
 * see uidls.h
 */

uidl_t *_uidl_new(void)
{
    uidl_t *uidl = xmalloc(sizeof(uidl_t));
    uidl->hostname = NULL;
    uidl->user = NULL;
    uidl->n = 0;
    uidl->uidv = NULL;
    return uidl;
}

uidl_t *uidl_new(const char *hostname, const char *user)
{
    uidl_t *uidl = _uidl_new();
    uidl->hostname = xstrdup(hostname);
    uidl->user = xstrdup(user);
    return uidl;
}


/*
 * uidl_free()
 *
 * see uidls.h
 */

void uidl_free(void *u)
{
    uidl_t *uidl = u;
    long i;
    
    if (uidl)
    {
	free(uidl->hostname);
	free(uidl->user);
        if (uidl->uidv)
	{
	    for (i = 0; i < uidl->n; i++)
	    {
		free(uidl->uidv[i]);
	    }
	    free(uidl->uidv);
	}
	free(uidl);
    }
}


/*
 * uidl_find()
 *
 * see uidls.h
 */

uidl_t *find_uidl(list_t *uidl_list, const char *hostname, const char *user)
{
    uidl_t *tmp;
    uidl_t *uidl = NULL;
    list_t *lp = uidl_list;

    while (!list_is_empty(lp))
    {
	lp = lp->next;
	tmp = lp->data;
	if (strcmp(tmp->hostname, hostname) == 0 
		&& strcmp(tmp->user, user) == 0)
	{
	    uidl = tmp;
	    break;
	}
    }

    return uidl;
}


/* Helper function for sorting a UID list with qsort() */
int _uidls_qsort_strcmp(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}


/*
 * uidls_read()
 *
 * see uidls.h
 */

int uidls_read(const char *filename, FILE **uidls_file, list_t **uidl_list, 
	char **errstr)
{
    char line[UIDLS_LINEBUFSIZE];
    long linecounter;
    uidl_t *uidl;
    long uidcounter;
    int sorted;
    list_t *lp;
    char *p, *q;
    long i;
    int e;
    
    uidcounter = 0;	/* shut up compiler warning */
    sorted = 1;		/* shut up compiler warning */

    *uidl_list = list_new();

    if (!(*uidls_file = fopen(filename, "r+")))
    {
	/* treat a nonexistant file as an empty file */
	if (!(*uidls_file = fopen(filename, "w+")))
	{
	    *errstr = xasprintf("%s: %s", filename, strerror(errno));
	    return UIDLS_EIO;
	}
	return UIDLS_EOK;
    }
    if ((e = lock_file(*uidls_file, TOOLS_LOCK_WRITE, UIDLS_LOCK_TIMEOUT)) != 0)
    {
	if (e == 1)
	{
	    *errstr = xasprintf(_("cannot lock %s (tried for %d seconds): %s"), 
		    filename, UIDLS_LOCK_TIMEOUT, strerror(errno));
	}
	else
	{
	    *errstr = xasprintf(_("cannot lock %s: %s"), 
		    filename, strerror(errno));
	}
	fclose(*uidls_file);
	return UIDLS_EIO;
    }

    lp = *uidl_list;
    uidl = NULL;
    linecounter = 0;
    e = UIDLS_EOK;
    while (fgets(line, (int)sizeof(line), *uidls_file))
    {
	linecounter++;
	if ((p = strchr(line, '\n')))
	{
	    *p = '\0';
	}
	else if (strlen(line) == UIDLS_LINEBUFSIZE - 1)
	{
	    *errstr = xasprintf(
		    _("%s, line %ld: line longer than %d characters"),
		    filename, linecounter, UIDLS_LINEBUFSIZE - 1);
	    e = UIDLS_EFORMAT;
	    break;
	}
	if (line[0] == '#')
	{
	    /* a comment */
	    continue;
	}
	
	if (!uidl)
	{
	    /* expecting " number-of-uids hostname user" */
	    if (line[0] != ' ')
	    {
		*errstr = xasprintf(_("%s, line %ld: UID without a list"), 
		    	filename, linecounter);
		e = UIDLS_EFORMAT;
		break;
	    }
	    uidl = _uidl_new();
	    errno = 0;
	    uidl->n = strtol(line + 1, &p, 10);
	    if (uidl->n < 1 || (uidl->n == LONG_MAX && errno == ERANGE)
		    || (p == line + 1) || *p != ' ')
	    {
		*errstr = xasprintf(_("%s, line %ld: invalid number of UIDs"),
			filename, linecounter);
		e = UIDLS_EFORMAT;
		uidl->n = 0;
		break;
	    }
	    uidl->uidv = xmalloc(uidl->n * sizeof(char *));
	    for (i = 0; i < uidl->n; i++)
	    {
		uidl->uidv[i] = NULL;
	    }		    
	    p++;
	    if (!(q = strchr(p, ' ')) || (q == p))
	    {
		*errstr = xasprintf(
			_("%s, line %ld: invalid or missing host name"), 
			filename, linecounter);
		e = UIDLS_EFORMAT;
		break;
	    }
	    uidl->hostname = xmalloc((q - p + 1) * sizeof(char));
	    strncpy(uidl->hostname, p, (size_t)(q - p));
	    uidl->hostname[q - p] = '\0';
	    p = q + 1;
	    if (*p == '\0' || *p == ' ' || strchr(p, ' '))
	    {
		*errstr = xasprintf(
			_("%s, line %ld: invalid or missing user name"),
			filename, linecounter);
		e = UIDLS_EFORMAT;
		break;
	    }
	    uidl->user = xstrdup(p);
	    uidcounter = 0;
	    sorted = 1;
	}
	else
	{
	    /* expecting a uid */
	    if (line[0] == ' ')
    	    {
		*errstr = xasprintf(_("%s, line %ld: too few UIDs "
			    "for user %s, host %s"),
			filename, linecounter, uidl->user, uidl->hostname);
		e = UIDLS_EFORMAT;
		break;
	    }
	    uidl->uidv[uidcounter] = xstrdup(line);
	    uidcounter++;
	    if (uidcounter >= 2 && sorted)
    	    {
  		if (strcmp(uidl->uidv[uidcounter - 2],
   			    uidl->uidv[uidcounter - 1]) > 0)
		{
		    sorted = 0;
 		}
 	    }
	    if (uidcounter == uidl->n)
	    {
		if (!sorted)
   		{
 		    /* This should only happen when we read an UIDLS written by
		     * a version <= 0.8.3. */
 		    qsort(uidl->uidv, (size_t)uidl->n, sizeof(char *),
  			    _uidls_qsort_strcmp);
 		}
		list_insert(lp, uidl);
		lp = lp->next;
		uidl = NULL;
	    }
	}
    }
    if (e == UIDLS_EOK && uidl)
    {
	*errstr = xasprintf(
		_("%s, line %ld: too few UIDs for user %s, host %s"),
		filename, linecounter, uidl->user, uidl->hostname);
	e = UIDLS_EFORMAT;
    }
    
    if (e != UIDLS_EOK)
    {
	(void)fclose(*uidls_file);
	uidl_free(uidl);
	list_xfree(*uidl_list, uidl_free);
     	return e;
    }
    else if (ferror(*uidls_file))
    {
	(void)fclose(*uidls_file);
	*errstr = xasprintf(_("%s: input error"), filename);
	uidl_free(uidl);
	list_xfree(*uidl_list, uidl_free);
	return UIDLS_EIO;
    }
    else
    {
	return UIDLS_EOK;
    }
}


/*
 * uidls_write()
 *
 * see uidls.h
 */

int uidls_write(const char *filename, FILE *uidls_file, list_t *uidl_list, 
	char **errstr)
{
    list_t *lp;
    uidl_t *uidl;
    long i;
    int error;

    if (fseek(uidls_file, 0, SEEK_SET) != 0 
	    || ftruncate(fileno(uidls_file), 0) != 0)
    {
	*errstr = xasprintf("%s: %s", filename, strerror(errno));
	return UIDLS_EOK;
    }

    error = (fprintf(uidls_file, 
		"# This file was generated by %s version %s.\n"
		"#\n"
		"# Lines starting with a space begin a new UID list and have\n"
		"# the following format: \" number-of-uids hostname user\".\n"
		"# The list of UIDs follows in ascending order, with one "
			"UID per line.\n"
		"#\n",
		PACKAGE_NAME, PACKAGE_VERSION) < 0);
    
    lp = uidl_list;
    while (!error && !list_is_empty(lp))
    {
	lp = lp->next;
	uidl = lp->data;
	if (uidl->n > 0)
	{
	    error = (fprintf(uidls_file, " %ld %s %s\n", 
			uidl->n, uidl->hostname, uidl->user) < 0);
	    qsort(uidl->uidv, (size_t)uidl->n, sizeof(char *), 
		    _uidls_qsort_strcmp);
	    for (i = 0; !error && i < uidl->n; i++)
	    {
		error = (fputs(uidl->uidv[i], uidls_file) == EOF 
			|| fputc((unsigned char)'\n', uidls_file) == EOF);
	    }
	}
    }

    if (error)
    {
	*errstr = xasprintf("%s: %s", filename, strerror(errno));
	(void)fclose(uidls_file);
	return UIDLS_EIO;
    }
    else
    {
	(void)fclose(uidls_file);
	return UIDLS_EOK;
    }
}
