/*-------------------------------------------------------------------------
 *
 * token_file.c
 *	  Reading the tokens compute_ctl writes to files outside pgdata.
 *
 * compute_ctl writes each token as `<token>\n` to its own file (mode 0600,
 * replaced by rename, so a reader opens either the old or the new inode and
 * always reads a whole file) and names the files in postgresql.conf:
 *
 *	neon.storage_auth_token_file	the tenant storage token: the password of
 *									every pageserver and safekeeper connection
 *	neon.compute_ctl_token_file		the secret of compute_ctl's internal server:
 *									the bearer of every call to it
 *
 * Both are PGC_POSTMASTER, so a session can't point the reader elsewhere. An
 * empty path means "no token configured": nothing is read and nothing is
 * logged (a compute started without storage auth).
 *
 * Each process caches the token it read together with the identity of the
 * file it read it from: {st_dev, st_ino, st_size, st_mtim, st_ctim}, taken
 * from fstat() of the open descriptor, never from the stat() before the open
 * (a stat of the old inode followed by an open of the new one must not cache
 * the new content under the old identity). Each call does one stat() of the
 * path; when the identity differs from the cached one the file is read again.
 * A replacement within one mtime tick is still seen: rename gives a new
 * inode, and it changes st_ctim.
 *
 * Fail closed: a missing, unreadable, empty, oversized or invalid file gives
 * no token, and the cached token is dropped. One WARNING names the path and
 * the reason (never the content) per state change; the file becoming usable
 * again is logged at LOG.
 *
 * A valid file holds one line of [A-Za-z0-9._~+/=-], 1-8191 bytes, with one
 * optional trailing '\n'; the whole file is at most 8 KiB. A symlink is
 * followed and its target read like a file.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

#include "utils/guc.h"

#include "token_file.h"

/* The whole file, trailing newline included. */
#define TOKEN_FILE_MAX_BYTES	8192
/* The token itself. */
#define TOKEN_MAX_LEN			(TOKEN_FILE_MAX_BYTES - 1)

#ifdef __APPLE__
#define ST_MTIM(st) ((st)->st_mtimespec)
#define ST_CTIM(st) ((st)->st_ctimespec)
#else
#define ST_MTIM(st) ((st)->st_mtim)
#define ST_CTIM(st) ((st)->st_ctim)
#endif

typedef enum TokenFileState
{
	TF_NONE = 0,				/* nothing decided yet, or no path configured */
	TF_VALID,
	TF_MISSING,
	TF_STAT_FAILED,
	TF_OPEN_FAILED,
	TF_NOT_REGULAR,
	TF_READ_FAILED,
	TF_EMPTY,
	TF_OVERSIZED,
	TF_INVALID,
} TokenFileState;

typedef struct TokenFileIdentity
{
	dev_t		dev;
	ino_t		ino;
	off_t		size;
	struct timespec mtim;
	struct timespec ctim;
} TokenFileIdentity;

typedef struct TokenFile
{
	const char *what;			/* for messages */
	const char *without;		/* what happens without the token */
	char	  **path;			/* the GUC variable */

	/* The state decided for the file with identity `ident`. */
	TokenFileState state;
	bool		has_ident;
	TokenFileIdentity ident;

	/* The state last reported, so each state is reported once. */
	TokenFileState reported;
	bool		reported_has_ident;
	TokenFileIdentity reported_ident;

	/* The token, when state == TF_VALID. */
	char		value[TOKEN_MAX_LEN + 1];
} TokenFile;

static char *storage_auth_token_file = NULL;
static char *compute_ctl_token_file = NULL;

static TokenFile storage_token = {
	.what = "storage auth token",
	.without = "pageserver and safekeeper connections go without a token",
	.path = &storage_auth_token_file,
};

static TokenFile compute_ctl_token = {
	.what = "compute_ctl token",
	.without = "calls to compute_ctl go without a token",
	.path = &compute_ctl_token_file,
};

/* Scratch space for a read; wiped after every use. */
static char read_buf[TOKEN_FILE_MAX_BYTES + 1];

void
pg_init_token_files(void)
{
	DefineCustomStringVariable("neon.storage_auth_token_file",
							   "File holding the tenant storage token for pageserver and safekeeper connections",
							   "Written by compute_ctl; empty means no storage token.",
							   &storage_auth_token_file,
							   "",
							   PGC_POSTMASTER,
							   0,
							   NULL, NULL, NULL);

	DefineCustomStringVariable("neon.compute_ctl_token_file",
							   "File holding the secret of compute_ctl's internal API",
							   "Written by compute_ctl; empty means no secret.",
							   &compute_ctl_token_file,
							   "",
							   PGC_POSTMASTER,
							   0,
							   NULL, NULL, NULL);
}

static void
identity_from_stat(TokenFileIdentity *id, const struct stat *st)
{
	memset(id, 0, sizeof(*id));
	id->dev = st->st_dev;
	id->ino = st->st_ino;
	id->size = st->st_size;
	id->mtim = ST_MTIM(st);
	id->ctim = ST_CTIM(st);
}

static bool
identity_equal(const TokenFileIdentity *a, const TokenFileIdentity *b)
{
	return a->dev == b->dev &&
		a->ino == b->ino &&
		a->size == b->size &&
		a->mtim.tv_sec == b->mtim.tv_sec &&
		a->mtim.tv_nsec == b->mtim.tv_nsec &&
		a->ctim.tv_sec == b->ctim.tv_sec &&
		a->ctim.tv_nsec == b->ctim.tv_nsec;
}

static bool
token_char(unsigned char c)
{
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '.' || c == '_' || c == '~' || c == '+' ||
		c == '/' || c == '=' || c == '-';
}

static void
forget_token(TokenFile *tf)
{
	explicit_bzero(tf->value, sizeof(tf->value));
}

/*
 * Records a failed state for the file with identity `id` (NULL when there is
 * no file to identify) and reports it unless it is the state last reported.
 * `err` is the errno of a failed system call, or 0.
 */
static void
token_file_fail(TokenFile *tf, const char *path, TokenFileState state,
				const TokenFileIdentity *id, int err)
{
	const char *reason;

	forget_token(tf);
	tf->state = state;
	tf->has_ident = (id != NULL);
	if (id != NULL)
		tf->ident = *id;
	else
		memset(&tf->ident, 0, sizeof(tf->ident));

	if (tf->reported == state &&
		tf->reported_has_ident == tf->has_ident &&
		(!tf->has_ident || identity_equal(&tf->reported_ident, &tf->ident)))
		return;

	tf->reported = state;
	tf->reported_has_ident = tf->has_ident;
	tf->reported_ident = tf->ident;

	switch (state)
	{
		case TF_MISSING:
			reason = "it does not exist";
			break;
		case TF_STAT_FAILED:
			reason = "could not stat it";
			break;
		case TF_OPEN_FAILED:
			reason = "could not open it";
			break;
		case TF_NOT_REGULAR:
			reason = "it is not a regular file";
			break;
		case TF_READ_FAILED:
			reason = "could not read it";
			break;
		case TF_EMPTY:
			reason = "it is empty";
			break;
		case TF_OVERSIZED:
			reason = "it is larger than 8 KiB or its token longer than 8191 bytes";
			break;
		case TF_INVALID:
			reason = "it is not one line of token characters";
			break;
		default:
			reason = "unknown state";
			break;
	}

	if (err != 0)
		ereport(WARNING,
				(errmsg("neon: could not use the %s file \"%s\": %s: %s",
						tf->what, path, reason, strerror(err)),
				 errdetail("Until the file is fixed, %s.", tf->without),
				 errhidestmt(true), errhidecontext(true)));
	else
		ereport(WARNING,
				(errmsg("neon: could not use the %s file \"%s\": %s",
						tf->what, path, reason),
				 errdetail("Until the file is fixed, %s.", tf->without),
				 errhidestmt(true), errhidecontext(true)));
}

/*
 * Reads the file at `path`, whose stat() gave `seen`, and decides its state.
 */
static void
token_file_read(TokenFile *tf, const char *path, const TokenFileIdentity *seen)
{
	struct stat st;
	TokenFileIdentity id;
	size_t		total = 0;
	size_t		len;
	int			fd;
	int			err;

	/* O_NONBLOCK: a FIFO put in the file's place must not hang the open. */
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
	{
		err = errno;
		if (err == ENOENT)
			token_file_fail(tf, path, TF_MISSING, NULL, 0);
		else
			token_file_fail(tf, path, TF_OPEN_FAILED, seen, err);
		return;
	}

	/* The identity is the descriptor's: what is read below is this inode. */
	if (fstat(fd, &st) != 0)
	{
		err = errno;
		close(fd);
		token_file_fail(tf, path, TF_STAT_FAILED, NULL, err);
		return;
	}
	identity_from_stat(&id, &st);

	if (!S_ISREG(st.st_mode))
	{
		close(fd);
		token_file_fail(tf, path, TF_NOT_REGULAR, &id, 0);
		return;
	}
	if (st.st_size > TOKEN_FILE_MAX_BYTES)
	{
		close(fd);
		token_file_fail(tf, path, TF_OVERSIZED, &id, 0);
		return;
	}

	/* Read one byte more than allowed, to see a file that grew. */
	while (total < sizeof(read_buf))
	{
		ssize_t		n = read(fd, read_buf + total, sizeof(read_buf) - total);

		if (n < 0)
		{
			if (errno == EINTR)
				continue;
			err = errno;
			close(fd);
			explicit_bzero(read_buf, sizeof(read_buf));
			token_file_fail(tf, path, TF_READ_FAILED, &id, err);
			return;
		}
		if (n == 0)
			break;
		total += n;
	}
	close(fd);

	if (total > TOKEN_FILE_MAX_BYTES)
	{
		explicit_bzero(read_buf, sizeof(read_buf));
		token_file_fail(tf, path, TF_OVERSIZED, &id, 0);
		return;
	}

	len = total;
	if (len > 0 && read_buf[len - 1] == '\n')
		len--;
	if (len == 0)
	{
		explicit_bzero(read_buf, sizeof(read_buf));
		token_file_fail(tf, path, TF_EMPTY, &id, 0);
		return;
	}
	if (len > TOKEN_MAX_LEN)
	{
		explicit_bzero(read_buf, sizeof(read_buf));
		token_file_fail(tf, path, TF_OVERSIZED, &id, 0);
		return;
	}
	for (size_t i = 0; i < len; i++)
	{
		if (!token_char((unsigned char) read_buf[i]))
		{
			explicit_bzero(read_buf, sizeof(read_buf));
			token_file_fail(tf, path, TF_INVALID, &id, 0);
			return;
		}
	}

	forget_token(tf);
	memcpy(tf->value, read_buf, len);
	tf->value[len] = '\0';
	explicit_bzero(read_buf, sizeof(read_buf));

	tf->state = TF_VALID;
	tf->has_ident = true;
	tf->ident = id;

	if (tf->reported != TF_NONE && tf->reported != TF_VALID)
		ereport(LOG,
				(errmsg("neon: the %s file \"%s\" is usable again", tf->what, path),
				 errhidestmt(true), errhidecontext(true)));
	tf->reported = TF_VALID;
	tf->reported_has_ident = true;
	tf->reported_ident = id;
}

static const char *
token_file_get(TokenFile *tf)
{
	const char *path = *tf->path;
	struct stat st;
	TokenFileIdentity seen;

	if (path == NULL || path[0] == '\0')
	{
		/* No file configured: no token, silently. */
		forget_token(tf);
		tf->state = TF_NONE;
		tf->has_ident = false;
		tf->reported = TF_NONE;
		tf->reported_has_ident = false;
		return NULL;
	}

	if (stat(path, &st) != 0)
	{
		int			err = errno;

		if (err == ENOENT)
			token_file_fail(tf, path, TF_MISSING, NULL, 0);
		else
			token_file_fail(tf, path, TF_STAT_FAILED, NULL, err);
		return NULL;
	}
	identity_from_stat(&seen, &st);

	/* The file the cached state was decided on: nothing to read. */
	if (tf->has_ident && identity_equal(&tf->ident, &seen))
		return tf->state == TF_VALID ? tf->value : NULL;

	token_file_read(tf, path, &seen);
	return tf->state == TF_VALID ? tf->value : NULL;
}

const char *
neon_storage_auth_token(void)
{
	return token_file_get(&storage_token);
}

const char *
neon_compute_ctl_token(void)
{
	return token_file_get(&compute_ctl_token);
}

struct curl_slist *
neon_compute_ctl_auth_headers(void)
{
	static const char prefix[] = "Authorization: Bearer ";
	char		header[sizeof(prefix) + TOKEN_MAX_LEN];
	const char *token = neon_compute_ctl_token();
	struct curl_slist *headers;
	size_t		len;

	if (token == NULL)
		return NULL;

	len = strlen(token);
	memcpy(header, prefix, sizeof(prefix) - 1);
	memcpy(header + sizeof(prefix) - 1, token, len + 1);
	headers = curl_slist_append(NULL, header);
	explicit_bzero(header, sizeof(header));
	if (headers == NULL)
		ereport(WARNING,
				(errmsg("neon: out of memory building the compute_ctl request header")));
	return headers;
}
