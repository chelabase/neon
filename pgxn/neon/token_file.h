/*-------------------------------------------------------------------------
 *
 * token_file.h
 *	  Reading the tokens compute_ctl writes to files outside pgdata.
 *
 * compute_ctl writes the tenant storage token and its internal API secret to
 * two files and names them in postgresql.conf (neon.storage_auth_token_file,
 * neon.compute_ctl_token_file). Each process keeps the last token it read,
 * keyed on the identity of the file it read; one stat() per call decides
 * whether the file must be read again.
 *
 *-------------------------------------------------------------------------
 */
#ifndef TOKEN_FILE_H
#define TOKEN_FILE_H

/* Registers neon.storage_auth_token_file and neon.compute_ctl_token_file. */
extern void pg_init_token_files(void);

/*
 * The current token, or NULL when no file is configured or the file can't be
 * used (fail closed). The pointer is valid until the next call of the same
 * function in this process. Never log what it points to.
 */
extern const char *neon_storage_auth_token(void);
extern const char *neon_compute_ctl_token(void);

/*
 * An `Authorization: Bearer <secret>` header list for a call to compute_ctl's
 * internal server, or NULL when there is no usable secret (the call then
 * goes without a header and is refused). Free with curl_slist_free_all().
 */
struct curl_slist;
extern struct curl_slist *neon_compute_ctl_auth_headers(void);

#endif							/* TOKEN_FILE_H */
