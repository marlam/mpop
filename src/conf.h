/*
 * conf.h
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

#ifndef CONF_H
#define CONF_H

#include "list.h"

/*
 * If a function with an 'errstr' argument returns a value != CONF_EOK,
 * '*errstr' either points to an allocates string containing an error 
 * description or is NULL.
 * If such a function returns CONF_EOK, 'errstr' will not be changed.
 */
#define CONF_EOK	0	/* no error */
#define CONF_EIO	1	/* Input/output error */
#define CONF_EPARSE	2	/* Parse error */
#define CONF_ESYNTAX	3	/* Syntax error */
#define CONF_EINSECURE	4	/* Insecure permissions */

/*
 * An account
 */
#define ACC_HOST		(1 << 0)
#define ACC_PORT		(1 << 1)
#define ACC_TIMEOUT		(1 << 2)
#define ACC_PIPELINING		(1 << 3)
#define ACC_DELIVERY		(1 << 4)
#define ACC_UIDLS_FILE		(1 << 5)
#define ACC_ONLY_NEW		(1 << 6)
#define ACC_KEEP		(1 << 7)
#define ACC_KILLSIZE		(1 << 8)
#define ACC_SKIPSIZE		(1 << 9)
#define ACC_FILTER		(1 << 10)
#define ACC_AUTH_MECH		(1 << 11)
#define ACC_USERNAME		(1 << 12)
#define ACC_PASSWORD		(1 << 13)
#define ACC_NTLMDOMAIN		(1 << 14)
#define ACC_TLS			(1 << 15)
#define ACC_TLS_KEY_FILE	(1 << 16)
#define ACC_TLS_CERT_FILE	(1 << 17)
#define ACC_TLS_TRUST_FILE	(1 << 18)
#define ACC_TLS_NOCERTCHECK	(1 << 19)
#define ACC_TLS_NOSTARTTLS	(1 << 20)
#define ACC_TLS_FORCE_SSLV3	(1 << 21)

typedef struct
{
    /* identification */
    char *id;			/* name of this account */
    char *conffile;		/* name of the configuration file of this 
				   account or NULL for command line */
    int mask;			/* combination of the above ACC_* flags.
				   Shows which settings were changed */
    /* POP3 server */
    char *host;			/* hostname of POP3 server */
    int port;			/* port number */
    int timeout;		/* connect/input/output timeout in seconds */
    /* POP3 settings */
    int pipelining;		/* use pipelining? 0=off, 1=on, 2=auto */
    int delivery_method;	/* number of the method, from delivery.h */
    char *delivery_args;	/* arguments for the delivery method */
    char *uidls_file;		/* file to store UIDLs */
    int only_new;		/* flag: retrieve only new messages? */
    int keep;			/* flag: keep messages on the server? */
    long killsize;		/* killsize, -1 when disabled */
    long skipsize;		/* skipsize, -1 when disabled */
    char *filter;		/* a program to filter the mail headers 
				   through */
    /* Authentication */
    char *auth_mech;		/* authentication mechanism */
    char *username;		/* username for authentication */
    char *password;		/* password for authentication */
    char *ntlmdomain;		/* domain for NTLM authentication */
    /* TLS / SSL */
    int tls;			/* flag: use TLS? */
    int tls_nostarttls;		/* flag: start TLS immediatly 
				   (without STARTTLS command)? */
    char *tls_key_file;		/* file in PEM format */
    char *tls_cert_file;	/* file in PEM format */
    char *tls_trust_file;	/* file in PEM format */
    int tls_nocertcheck;	/* flag: do not check certificate? */
    int tls_force_sslv3;	/* flag: force SSLv3? */
} account_t;

/* 
 * account_new()
 * 
 * Create a new account_t. Built-in default values are filled in, except for
 * settings whose default values are not yet known. These are port and
 * uidls_file at the moment.
 * Must be freed with account_free().
 * Both arguments may be NULL.
 */
account_t *account_new(const char *conffile, const char *id);

/*
 * account_copy()
 *
 * Create a new account which is a copy of 'acc'.
 * If 'acc' is NULL, NULL is returned.
 */
account_t *account_copy(account_t *acc);

/* 
 * account_free()
 * 
 * Free an account_t.
 */
void account_free(void *a);

/*
 * find_account()
 * 
 * Find an account in a list of accounts by its id.
 * Returns the account or NULL.
 */
account_t *find_account(list_t *acc_list, const char *id);

/*
 * is_on(), is_off()
 *
 * Check whether the given string is "on" or "off"
 */
int is_on(char *s);
int is_off(char *s);

/*
 * check_auth_arg()
 *
 * checks if the given string is a proper argument to the auth command.
 * If so, the string is converted to uppercase and 0 is returned. Otherwise, 1
 * is returned.
 * Note that you have to check whether the arg is "off" separately, because 
 * that value results in NULL.
 */
int check_auth_arg(char *arg);

/*
 * get_non_neg_int()
 *
 * Gets a non-negative integer. Returns -1 on error.
 */
int get_non_neg_int(const char *arg);

/*
 * get_size_arg()
 *
 * Gets a size argument. Returns -1 on error.
 */
long get_size_arg(const char *arg);

/*
 * override_account()
 *
 * Override the settings of 'acc1' with the settings of 'acc2' when the
 * appropriate flag ist set in acc2->mask.
 * The flags from acc2->mask will also be set in acc1->mask.
 */
void override_account(account_t *acc1, account_t *acc2);

/*
 * check_account()
 * 
 * Check an account_t. 'retrmail' must indicate whether mpop works in mail
 * retrieval mode, because some checks depend on this.
 * If this function returns CONF_ESYNTAX, *errstr will always point to an
 * error string.
 * Used error codes: CONF_ESYNTAX
 */
int check_account(account_t *acc, int retrmail, char **errstr);

/*
 * get_conf()
 * 
 * Read 'conffile' and store all account data in 'acc_list'.
 * If 'securitycheck' is set, the file must not have more permissions than 0600,
 * must be a regular file and owned by the current user.
 * Used error codes: CONF_EIO, CONF_EPARSE, CONF_ESYNTAX
 */
int get_conf(const char *conffile, int securitycheck, list_t **acc_list, 
	char **errstr);

#endif
