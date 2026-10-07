/*-------------------------------------------------------------------------
 *
 * neon_ddl_handler.c
 *	  Captures updates to roles/databases using ProcessUtility_hook and
 *        sends them to the control ProcessUtility_hook. The changes are sent
 *        via HTTP to the URL specified by the GUC neon.console_url when the
 *        transaction commits. Forwarding may be disabled temporarily by
 *        setting neon.forward_ddl to false.
 *
 *        Currently, the transaction may abort AFTER
 *        changes have already been forwarded, and that case is not handled.
 *        Subtransactions are handled using a stack of hash tables, which
 *        accumulate changes. On subtransaction commit, the top of the stack
 *        is merged with the table below it.
 *
 *    Support event triggers for {privileged_role_name}
 *
 * IDENTIFICATION
 *	 contrib/neon/neon_dll_handler.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include <curl/curl.h>
#include <unistd.h>

#include "access/xact.h"
#include "catalog/pg_authid.h"
#include "catalog/pg_proc.h"
#include "commands/defrem.h"
#include "commands/event_trigger.h"
#include "commands/user.h"
#include "fmgr.h"
#include "libpq/crypt.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "parser/parse_func.h"
#include "tcop/pquery.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/guc.h"
#include "utils/hsearch.h"
#include "utils/memutils.h"
#include "utils/jsonb.h"
#include <utils/lsyscache.h>
#include <utils/syscache.h>

#include "neon_ddl_handler.h"
#include "neon_utils.h"
#include "neon.h"

static ProcessUtility_hook_type PreviousProcessUtilityHook = NULL;
static fmgr_hook_type next_fmgr_hook = NULL;
static needs_fmgr_hook_type next_needs_fmgr_hook = NULL;
static bool neon_event_triggers = true;

static const char *jwt_token = NULL;

/* GUCs */
static char *ConsoleURL = NULL;
static bool ForwardDDL = true;
static char *ProtectedDatabases = NULL;
static bool RegressTestMode = false;

/*
 * CURL docs say that this buffer must exist until we call curl_easy_cleanup
 * (which we never do), so we make this a static
 */
static char CurlErrorBuf[CURL_ERROR_SIZE];

typedef enum
{
	Op_Set,						/* An upsert: Either a creation or an alter */
	Op_Delete,
} OpType;

typedef struct
{
	char		name[NAMEDATALEN];
	Oid			owner;
	char		old_name[NAMEDATALEN];
	OpType		type;
} DbEntry;

/*
 * Roles are tracked by OID, never by name: a transaction can drop a role,
 * rename another one onto its name, create a third under it and rename that
 * one away, and keying by name mixed those roles' state (lost DROPs, data
 * keys passed to a new role, a dropped role's attributes sent for another).
 *
 * RoleIdentities (the whole top-level transaction, never rolled back) holds,
 * for every role a statement touched, its name before the transaction (the
 * name at its first touch: any rename is a touch) or that the transaction
 * created it. A subtransaction's rollback needs no undo: at commit the
 * catalog, looked up by OID, says which roles exist and under which names.
 *
 * The per-(sub)transaction role tables hold what only the statements know
 * (the password as typed, which options were given), by OID, and follow the
 * subtransactions: a released one's merge into its parent, a rolled-back
 * one's are dropped.
 */
typedef struct
{
	Oid			oid;			/* hash key */
	/* The name before the transaction; unused when created */
	char		orig_name[NAMEDATALEN];
	bool		created;
} RoleIdentity;

typedef struct
{
	Oid			oid;			/* hash key */

	/*
	 * The last PASSWORD clause (of CREATE or ALTER) decides: its text, or
	 * NULL for PASSWORD NULL. Whether the role has a password at commit comes
	 * from the catalog.
	 */
	const char *password;
	bool		password_set;
	/* LOGIN or NOLOGIN was given; the value sent is the catalog's at commit */
	bool		login_set;
	/* VALID UNTIL, as written (the last one given); NULL when not given */
	const char *valid_until;

	/*
	 * Another attribute (CREATEDB, CREATEROLE, INHERIT, REPLICATION,
	 * BYPASSRLS, SUPERUSER, CONNECTION LIMIT) or a role membership changed:
	 * the receiver resyncs the branch's roles from the catalog.
	 */
	bool		touched;
} RoleAttrs;

/*
 * We keep one of these for each subtransaction in a stack. When a subtransaction
 * commits, we merge the top of the stack into the table below it. It is allocated in the
 * subtransaction's context.
 */
typedef struct DdlHashTable
{
	struct DdlHashTable *prev_table;
	size_t		subtrans_level;
	HTAB	   *db_table;
	HTAB	   *role_table;		/* RoleAttrs by OID */
} DdlHashTable;

static DdlHashTable RootTable;
static DdlHashTable *CurrentDdlTable = &RootTable;
static int SubtransLevel; /* current nesting level of subtransactions */
static HTAB *RoleIdentities;	/* RoleIdentity by OID, in TopTransactionContext */

static void
PushKeyNull(JsonbParseState **state, char *key)
{
	JsonbValue	k,
				v;

	k.type = jbvString;
	k.val.string.len = strlen(key);
	k.val.string.val = key;
	v.type = jbvNull;
	pushJsonbValue(state, WJB_KEY, &k);
	pushJsonbValue(state, WJB_VALUE, &v);
}

static void
PushKeyValue(JsonbParseState **state, char *key, char *value)
{
	JsonbValue	k,
				v;

	k.type = jbvString;
	k.val.string.len = strlen(key);
	k.val.string.val = key;
	v.type = jbvString;
	v.val.string.len = strlen(value);
	v.val.string.val = value;
	pushJsonbValue(state, WJB_KEY, &k);
	pushJsonbValue(state, WJB_VALUE, &v);
}

static void
PushKeyBool(JsonbParseState **state, char *key, bool value)
{
	JsonbValue	k,
				v;

	k.type = jbvString;
	k.val.string.len = strlen(key);
	k.val.string.val = key;
	v.type = jbvBool;
	v.val.boolean = value;
	pushJsonbValue(state, WJB_KEY, &k);
	pushJsonbValue(state, WJB_VALUE, &v);
}

/* A new entry that knows nothing yet: the parent's state stays */
static void
InitRoleAttrs(RoleAttrs *attrs)
{
	attrs->password = NULL;
	attrs->password_set = false;
	attrs->login_set = false;
	attrs->valid_until = NULL;
	attrs->touched = false;
}

/* What became of a role the transaction touched, read from the catalog at commit */
typedef struct
{
	Oid			oid;
	const char *orig_name;		/* NULL when created */
	bool		exists;
	char		name[NAMEDATALEN];	/* the name at commit, when it exists */
	bool		canlogin;
	bool		has_password;
	RoleAttrs  *attrs;			/* NULL when no option was given */
} RoleOutcome;

/* A role that exists at commit has this name */
static bool
NameTaken(RoleOutcome *outcomes, int count, const char *name)
{
	for (int i = 0; i < count; i++)
	{
		if (outcomes[i].exists && strcmp(outcomes[i].name, name) == 0)
			return true;
	}
	return false;
}

/* A role that held this name before the transaction is gone */
static bool
NameOfDroppedRole(RoleOutcome *outcomes, int count, const char *name)
{
	for (int i = 0; i < count; i++)
	{
		if (!outcomes[i].exists && outcomes[i].orig_name != NULL &&
			strcmp(outcomes[i].orig_name, name) == 0)
			return true;
	}
	return false;
}

/*
 * The roles' outcomes, one per touched role, from the catalog. Returns the
 * count; *out is palloc'd.
 */
static int
RoleOutcomes(RoleOutcome **out)
{
	HASH_SEQ_STATUS status;
	RoleIdentity *id;
	RoleOutcome *outcomes;
	int			count = 0;

	if (!RoleIdentities)
	{
		*out = NULL;
		return 0;
	}
	outcomes = palloc0(sizeof(RoleOutcome) * Max(hash_get_num_entries(RoleIdentities), 1));
	hash_seq_init(&status, RoleIdentities);
	while ((id = hash_seq_search(&status)) != NULL)
	{
		RoleOutcome *o = &outcomes[count++];
		HeapTuple	tuple = SearchSysCache1(AUTHOID, ObjectIdGetDatum(id->oid));

		o->oid = id->oid;
		o->orig_name = id->created ? NULL : id->orig_name;
		if (HeapTupleIsValid(tuple))
		{
			Form_pg_authid form = (Form_pg_authid) GETSTRUCT(tuple);
			bool		isnull;

			o->exists = true;
			strlcpy(o->name, NameStr(form->rolname), NAMEDATALEN);
			o->canlogin = form->rolcanlogin;
			(void) SysCacheGetAttr(AUTHOID, tuple, Anum_pg_authid_rolpassword, &isnull);
			o->has_password = !isnull;
			ReleaseSysCache(tuple);
		}
		if (RootTable.role_table)
			o->attrs = hash_search(RootTable.role_table, &id->oid, HASH_FIND, NULL);
	}
	*out = outcomes;
	return count;
}

/*
 * Pushes the role's entry, if it has one. Returns whether it did (with
 * state NULL it only tells).
 *
 * - A role created in the transaction that exists at commit: a set under its
 *   name, never an old_name (no receiver row is its own), with its password
 *   (or an explicit null) and its login, and "recreated" (with "touched")
 *   when a role that held the name before the transaction is gone.
 * - A role from before the transaction that exists at commit: a set with its
 *   old_name when renamed, the password when a PASSWORD clause was given,
 *   login (the catalog's) when LOGIN or NOLOGIN was given, valid_until, and
 *   "touched" for other options and memberships, or when it took the name
 *   of a role that is gone (whose members lost their membership).
 * - A role from before the transaction that is gone: a del under its name
 *   before the transaction, unless a role now has that name (a set with
 *   recreated, or a rename onto it, which the receiver refuses or replaces
 *   when it moves its rows).
 */
static bool
PushRoleEntry(JsonbParseState **state, RoleOutcome *outcomes, int count, RoleOutcome *o)
{
	RoleAttrs  *attrs = o->attrs;
	bool		created = o->orig_name == NULL;
	bool		renamed;
	bool		replaces_dropped;
	bool		password_set;
	bool		login;
	bool		touched;

	if (!o->exists)
	{
		if (created || NameTaken(outcomes, count, o->orig_name))
			return false;
		if (state)
		{
			pushJsonbValue(state, WJB_BEGIN_OBJECT, NULL);
			PushKeyValue(state, "op", "del");
			PushKeyValue(state, "name", (char *) o->orig_name);
			pushJsonbValue(state, WJB_END_OBJECT, NULL);
		}
		return true;
	}

	renamed = !created && strcmp(o->orig_name, o->name) != 0;
	replaces_dropped = NameOfDroppedRole(outcomes, count, o->name);
	password_set = created || (attrs && attrs->password_set);
	login = created || (attrs && attrs->login_set);
	touched = (attrs && attrs->touched) || replaces_dropped;
	if (!created && !renamed && !password_set && !login &&
		!(attrs && attrs->valid_until) && !touched)
		return false;
	if (!state)
		return true;

	pushJsonbValue(state, WJB_BEGIN_OBJECT, NULL);
	PushKeyValue(state, "op", "set");
	PushKeyValue(state, "name", o->name);
	if (password_set)
	{
		const char *plain = attrs ? attrs->password : NULL;

		if (o->has_password && plain)
		{
#if PG_MAJORVERSION_NUM == 14
			char	   *logdetail;
#else
			const char *logdetail;
#endif
			char	   *encrypted_password = get_role_password(o->name, &logdetail);

			if (!encrypted_password)
				elog(ERROR, "Failed to get encrypted password: %s", logdetail);
			PushKeyValue(state, "password", (char *) plain);
			PushKeyValue(state, "encrypted_password", encrypted_password);
		}
		else if (created || renamed || login || (attrs && attrs->valid_until) || touched)
		{
			/*
			 * No password (or none whose text this transaction typed): an
			 * explicit null. A plain PASSWORD NULL with nothing else is the
			 * entry without a password key, as before.
			 */
			if (o->has_password)
				elog(LOG, "role \"%s\" has a password this transaction didn't set", o->name);
			PushKeyNull(state, "password");
		}
	}
	if (renamed)
		PushKeyValue(state, "old_name", (char *) o->orig_name);
	if (login)
		PushKeyBool(state, "login", o->canlogin);
	if (attrs && attrs->valid_until)
		PushKeyValue(state, "valid_until", (char *) attrs->valid_until);
	if (touched)
		PushKeyBool(state, "touched", true);
	if (created && replaces_dropped)
		PushKeyBool(state, "recreated", true);
	pushJsonbValue(state, WJB_END_OBJECT, NULL);
	return true;
}

/* NULL when there is nothing to send */
static char *
ConstructDeltaMessage()
{
	JsonbParseState *state = NULL;
	RoleOutcome *outcomes;
	int			count = RoleOutcomes(&outcomes);
	bool		any_role = false;

	for (int i = 0; i < count && !any_role; i++)
		any_role = PushRoleEntry(NULL, outcomes, count, &outcomes[i]);
	if (!RootTable.db_table && !any_role)
		return NULL;

	pushJsonbValue(&state, WJB_BEGIN_OBJECT, NULL);
	if (RootTable.db_table)
	{
		JsonbValue	dbs;
		HASH_SEQ_STATUS status;
		DbEntry    *entry;

		dbs.type = jbvString;
		dbs.val.string.val = "dbs";
		dbs.val.string.len = strlen(dbs.val.string.val);
		pushJsonbValue(&state, WJB_KEY, &dbs);
		pushJsonbValue(&state, WJB_BEGIN_ARRAY, NULL);

		hash_seq_init(&status, RootTable.db_table);
		while ((entry = hash_seq_search(&status)) != NULL)
		{
			pushJsonbValue(&state, WJB_BEGIN_OBJECT, NULL);
			PushKeyValue(&state, "op", entry->type == Op_Set ? "set" : "del");
			PushKeyValue(&state, "name", entry->name);
			if (entry->owner != InvalidOid)
			{
				PushKeyValue(&state, "owner", GetUserNameFromId(entry->owner, false));
			}
			if (entry->old_name[0] != '\0')
			{
				PushKeyValue(&state, "old_name", entry->old_name);
			}
			pushJsonbValue(&state, WJB_END_OBJECT, NULL);
		}
		pushJsonbValue(&state, WJB_END_ARRAY, NULL);
	}

	if (any_role)
	{
		JsonbValue	roles;

		roles.type = jbvString;
		roles.val.string.val = "roles";
		roles.val.string.len = strlen(roles.val.string.val);
		pushJsonbValue(&state, WJB_KEY, &roles);
		pushJsonbValue(&state, WJB_BEGIN_ARRAY, NULL);
		for (int i = 0; i < count; i++)
			PushRoleEntry(&state, outcomes, count, &outcomes[i]);
		pushJsonbValue(&state, WJB_END_ARRAY, NULL);
	}
	{
		JsonbValue *result = pushJsonbValue(&state, WJB_END_OBJECT, NULL);
		Jsonb	   *jsonb = JsonbValueToJsonb(result);

		return JsonbToCString(NULL, &jsonb->root, 0 /* estimated_len */ );
	}
}

#define ERROR_SIZE 1024

static inline bool
IsHttpBodySpace(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

typedef struct
{
	char		str[ERROR_SIZE];
	size_t		size;
} ErrorString;

static size_t
ErrorWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	/* Docs say size is always 1 */
	ErrorString *str = userdata;

	size_t		to_write = nmemb;

	/* +1 for null terminator */
	if (str->size + nmemb + 1 >= ERROR_SIZE)
		to_write = ERROR_SIZE - str->size - 1;

	/* Ignore everyrthing past the first ERROR_SIZE bytes */
	if (to_write == 0)
		return nmemb;
	memcpy(str->str + str->size, ptr, to_write);
	str->size += to_write;
	str->str[str->size] = '\0';
	return nmemb;
}

static void
SendDeltasToControlPlane()
{
	static CURL		*handle = NULL;

	char	   *message;

	if (!RootTable.db_table && !RoleIdentities)
		return;
	if (!ConsoleURL)
	{
		elog(LOG, "ConsoleURL not set, skipping forwarding");
		return;
	}
	if (!ForwardDDL)
		return;
	message = ConstructDeltaMessage();
	if (!message)
		return;

	if (handle == NULL)
	{
		struct curl_slist *headers = NULL;

		headers = curl_slist_append(headers, "Content-Type: application/json");
		if (headers == NULL)
		{
			elog(ERROR, "Failed to set Content-Type header");
		}

		if (jwt_token)
		{
			char		auth_header[8192];

			snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", jwt_token);
			headers = curl_slist_append(headers, auth_header);
			if (headers == NULL)
			{
				elog(ERROR, "Failed to set Authorization header");
			}
		}

		handle = alloc_curl_handle();

		curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PATCH");
		curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(handle, CURLOPT_URL, ConsoleURL);
		curl_easy_setopt(handle, CURLOPT_ERRORBUFFER, CurlErrorBuf);
		curl_easy_setopt(handle, CURLOPT_TIMEOUT, 3L /* seconds */ );
		curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, ErrorWriteCallback);
	}

	{
		ErrorString str;
		const int	num_retries = 5;
		CURLcode	curl_status;
		long		response_code;

		str.size = 0;

		curl_easy_setopt(handle, CURLOPT_POSTFIELDS, message);
		curl_easy_setopt(handle, CURLOPT_WRITEDATA, &str);

		for (int i = 0; i < num_retries; i++)
		{
			if ((curl_status = curl_easy_perform(handle)) == 0)
				break;
			elog(LOG, "Curl request failed on attempt %d: %s", i, CurlErrorBuf);
			pg_usleep(1000 * 1000);
		}
		if (curl_status != CURLE_OK)
		{
			/* Details (the URL included) go to the server log only */
			elog(LOG, "Failed to perform curl request to %s: %s", ConsoleURL, CurlErrorBuf);
			ereport(ERROR,
					(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
					 errmsg("role and database changes are unavailable right now; try again")));
		}

		if (curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_UNKNOWN_OPTION)
		{
			if (response_code != 200)
			{
				elog(LOG, "Received HTTP code %ld from control plane: %s",
					 response_code,
					 str.size != 0 ? str.str : "");
				/*
				 * The control plane's message goes to the client, with
				 * surrounding whitespace trimmed; a whitespace-only body
				 * counts as empty. The body was cut at ERROR_SIZE - 1 bytes,
				 * possibly inside a multibyte character: drop the incomplete
				 * character.
				 */
				{
					char	   *msg = str.str;
					size_t		len = pg_mbcliplen(str.str, str.size, str.size);

					while (len > 0 && IsHttpBodySpace(msg[len - 1]))
						len--;
					msg[len] = '\0';
					while (*msg != '\0' && IsHttpBodySpace(*msg))
						msg++;

					if (*msg != '\0')
						ereport(ERROR,
								(errmsg_internal("%s", msg)));
				}
				ereport(ERROR,
						(errmsg("role and database changes were refused (HTTP %ld)",
								response_code)));
			}
		}
	}
}

static void
InitCurrentDdlTableIfNeeded()
{
	/* Lazy construction of DllHashTable chain */
	if (SubtransLevel > CurrentDdlTable->subtrans_level)
	{
		DdlHashTable *new_table = MemoryContextAlloc(CurTransactionContext, sizeof(DdlHashTable));
		new_table->prev_table = CurrentDdlTable;
		new_table->subtrans_level = SubtransLevel;
		new_table->role_table = NULL;
		new_table->db_table = NULL;
		CurrentDdlTable = new_table;
	}
}

static void
InitDbTableIfNeeded()
{
	InitCurrentDdlTableIfNeeded();
	if (!CurrentDdlTable->db_table)
	{
		HASHCTL		db_ctl = {};

		db_ctl.keysize = NAMEDATALEN;
		db_ctl.entrysize = sizeof(DbEntry);
		db_ctl.hcxt = CurTransactionContext;
		CurrentDdlTable->db_table = hash_create(
												"Dbs Created",
												4,
												&db_ctl,
												HASH_ELEM | HASH_STRINGS | HASH_CONTEXT);
	}
}

static void
InitRoleTableIfNeeded()
{
	InitCurrentDdlTableIfNeeded();
	if (!CurrentDdlTable->role_table)
	{
		HASHCTL		role_ctl = {};

		role_ctl.keysize = sizeof(Oid);
		role_ctl.entrysize = sizeof(RoleAttrs);
		role_ctl.hcxt = CurTransactionContext;
		CurrentDdlTable->role_table = hash_create(
												  "Role Options",
												  4,
												  &role_ctl,
												  HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	}
}

/* The role's options entry in the current (sub)transaction's table */
static RoleAttrs *
RoleAttrsFor(Oid oid)
{
	bool		found = false;
	RoleAttrs  *attrs;

	InitRoleTableIfNeeded();
	attrs = hash_search(CurrentDdlTable->role_table, &oid, HASH_ENTER, &found);
	if (!found)
		InitRoleAttrs(attrs);
	return attrs;
}

/* The role's identity entry, made when missing (found tells whether it was there) */
static RoleIdentity *
RoleIdentityFor(Oid oid, bool *found)
{
	if (!RoleIdentities)
	{
		HASHCTL		ctl = {};

		ctl.keysize = sizeof(Oid);
		ctl.entrysize = sizeof(RoleIdentity);
		ctl.hcxt = TopTransactionContext;
		RoleIdentities = hash_create("Role Identities", 8, &ctl,
									 HASH_ELEM | HASH_BLOBS | HASH_CONTEXT);
	}
	return hash_search(RoleIdentities, &oid, HASH_ENTER, found);
}

/*
 * Called before a statement that changes, renames, drops or grants an
 * existing role: at the role's first touch in the transaction its current
 * name is its name before the transaction. Returns the OID, or InvalidOid
 * when there is no such role (the statement then fails, or does nothing with
 * IF EXISTS).
 */
static Oid
TouchExistingRole(const char *role_name)
{
	Oid			oid = get_role_oid(role_name, true);
	bool		found = false;
	RoleIdentity *id;

	if (!OidIsValid(oid))
		return InvalidOid;
	id = RoleIdentityFor(oid, &found);
	if (!found)
	{
		strlcpy(id->orig_name, role_name, NAMEDATALEN);
		id->created = false;
	}
	return oid;
}

static void
PushTable()
{
	SubtransLevel += 1;
}

static void
MergeTable()
{
	DdlHashTable *old_table;

	Assert(SubtransLevel >= CurrentDdlTable->subtrans_level);
	if (--SubtransLevel >= CurrentDdlTable->subtrans_level)
	{
		return;
	}

	old_table = CurrentDdlTable;
	CurrentDdlTable = old_table->prev_table;

	if (old_table->db_table)
	{
		DbEntry    *entry;
		HASH_SEQ_STATUS status;

		InitDbTableIfNeeded();

		hash_seq_init(&status, old_table->db_table);
		while ((entry = hash_seq_search(&status)) != NULL)
		{
			bool		found_parent = false;
			DbEntry    *to_write = hash_search(
											   CurrentDdlTable->db_table,
											   entry->name,
											   HASH_ENTER,
											   &found_parent);

			if (!found_parent)
			{
				to_write->owner = InvalidOid;
				memset(to_write->old_name, 0, sizeof(to_write->old_name));
			}
			to_write->type = entry->type;
			if (entry->owner != InvalidOid)
				to_write->owner = entry->owner;

			/*
			 * An entry without old_name (e.g. an ALTER after a rename in the
			 * parent) must keep the parent's old_name.
			 */
			if (entry->old_name[0] != '\0')
			{
				bool		found_old = false;
				DbEntry    *old = hash_search(
											  CurrentDdlTable->db_table,
											  entry->old_name,
											  HASH_FIND,
											  &found_old);

				strlcpy(to_write->old_name, entry->old_name, NAMEDATALEN);
				if (found_old)
				{
					if (old->old_name[0] != '\0')
						strlcpy(to_write->old_name, old->old_name, NAMEDATALEN);
					else
						strlcpy(to_write->old_name, entry->old_name, NAMEDATALEN);
					hash_search(
								CurrentDdlTable->db_table,
								entry->old_name,
								HASH_REMOVE,
								NULL);
				}
			}
		}
		hash_destroy(old_table->db_table);
	}

	/*
	 * Role options are by OID, so a rename needs nothing here: what this
	 * subtransaction gave wins, touched is OR-ed, and an entry that gave no
	 * PASSWORD clause keeps the parent's password.
	 */
	if (old_table->role_table)
	{
		RoleAttrs  *entry;
		HASH_SEQ_STATUS status;

		InitRoleTableIfNeeded();
		hash_seq_init(&status, old_table->role_table);
		while ((entry = hash_seq_search(&status)) != NULL)
		{
			bool		found_parent = false;
			RoleAttrs  *to_write = hash_search(CurrentDdlTable->role_table,
											   &entry->oid,
											   HASH_ENTER,
											   &found_parent);

			if (!found_parent)
				InitRoleAttrs(to_write);
			if (entry->password_set)
			{
				to_write->password = entry->password;
				to_write->password_set = true;
			}
			to_write->login_set |= entry->login_set;
			if (entry->valid_until)
				to_write->valid_until = entry->valid_until;
			to_write->touched |= entry->touched;
		}
		hash_destroy(old_table->role_table);
	}
}

static void
PopTable()
{
	Assert(SubtransLevel >= CurrentDdlTable->subtrans_level);
	if (--SubtransLevel < CurrentDdlTable->subtrans_level)
	{
		/*
		 * Current table gets freed because it is allocated in aborted
		 * subtransaction's memory context.
		 */
		CurrentDdlTable = CurrentDdlTable->prev_table;
	}
}

static void
NeonSubXactCallback(
					SubXactEvent event,
					SubTransactionId mySubid,
					SubTransactionId parentSubid,
					void *arg)
{
	switch (event)
	{
		case SUBXACT_EVENT_START_SUB:
			return PushTable();
		case SUBXACT_EVENT_COMMIT_SUB:
			return MergeTable();
		case SUBXACT_EVENT_ABORT_SUB:
			return PopTable();
		default:
			return;
	}
}

static void
NeonXactCallback(XactEvent event, void *arg)
{
	if (event == XACT_EVENT_PRE_COMMIT || event == XACT_EVENT_PARALLEL_PRE_COMMIT)
	{
		SendDeltasToControlPlane();
	}
	RootTable.role_table = NULL;
	RootTable.db_table = NULL;
	RoleIdentities = NULL;		/* freed with TopTransactionContext */
	Assert(CurrentDdlTable == &RootTable);
}

static bool
IsPrivilegedRole(const char *role_name)
{
	Assert(role_name);

	return strcmp(role_name, privileged_role_name) == 0;
}

static void
HandleCreateDb(CreatedbStmt *stmt)
{
	DefElem    *downer = NULL;
	ListCell   *option;
	bool		found = false;
	DbEntry    *entry;

	InitDbTableIfNeeded();

	foreach(option, stmt->options)
	{
		DefElem    *defel = lfirst(option);

		if (strcmp(defel->defname, "owner") == 0)
			downer = defel;
	}

	entry = hash_search(CurrentDdlTable->db_table,
						stmt->dbname,
						HASH_ENTER,
						&found);
	if (!found)
		memset(entry->old_name, 0, sizeof(entry->old_name));

	entry->type = Op_Set;
	if (downer && downer->arg)
	{
		const char *owner_name = defGetString(downer);

		if (IsPrivilegedRole(owner_name))
			elog(ERROR, "could not create a database with owner %s", privileged_role_name);

		entry->owner = get_role_oid(owner_name, false);
	}
	else
	{
		entry->owner = GetUserId();
	}
}

static void
HandleAlterOwner(AlterOwnerStmt *stmt)
{
	const char *name;
	bool		found = false;
	DbEntry    *entry;
	const char *new_owner;

	if (stmt->objectType != OBJECT_DATABASE)
		return;
	InitDbTableIfNeeded();

	name = strVal(stmt->object);
	entry = hash_search(CurrentDdlTable->db_table,
						name,
						HASH_ENTER,
						&found);
	if (!found)
		memset(entry->old_name, 0, sizeof(entry->old_name));

	new_owner = get_rolespec_name(stmt->newowner);
	if (IsPrivilegedRole(new_owner))
		elog(ERROR, "could not alter owner to %s", privileged_role_name);

	entry->owner = get_role_oid(new_owner, false);
	entry->type = Op_Set;
}

static void
HandleDbRename(RenameStmt *stmt)
{
	bool		found = false;
	DbEntry    *entry;
	DbEntry    *entry_for_new_name;

	Assert(stmt->renameType == OBJECT_DATABASE);
	InitDbTableIfNeeded();
	entry = hash_search(CurrentDdlTable->db_table,
						stmt->subname,
						HASH_FIND,
						&found);

	entry_for_new_name = hash_search(CurrentDdlTable->db_table,
									 stmt->newname,
									 HASH_ENTER,
									 NULL);
	entry_for_new_name->type = Op_Set;

	if (found)
	{
		if (entry->old_name[0] != '\0')
			strlcpy(entry_for_new_name->old_name, entry->old_name, NAMEDATALEN);
		else
			strlcpy(entry_for_new_name->old_name, entry->name, NAMEDATALEN);
		entry_for_new_name->owner = entry->owner;
		hash_search(CurrentDdlTable->db_table,
					stmt->subname,
					HASH_REMOVE,
					NULL);
	}
	else
	{
		strlcpy(entry_for_new_name->old_name, stmt->subname, NAMEDATALEN);
		entry_for_new_name->owner = InvalidOid;
	}
}

static void
HandleDropDb(DropdbStmt *stmt)
{
	bool		found = false;
	DbEntry    *entry;

	InitDbTableIfNeeded();

	entry = hash_search(CurrentDdlTable->db_table,
						stmt->dbname,
						HASH_ENTER,
						&found);
	entry->type = Op_Delete;
	entry->owner = InvalidOid;
	if (!found)
		memset(entry->old_name, 0, sizeof(entry->old_name));
}

/*
 * Role options (as CREATE ROLE and ALTER ROLE name them) that the receiver
 * doesn't get as values: changing one marks the role touched. The last three
 * are memberships (CREATE ROLE ... IN ROLE / ROLE / ADMIN, ALTER GROUP).
 */
static bool
IsTouchingRoleOption(const char *defname)
{
	static const char *const touching[] = {
		"createdb", "createrole", "inherit", "isreplication", "bypassrls",
		"superuser", "connectionlimit",
		"addroleto", "rolemembers", "adminmembers",
	};

	for (size_t i = 0; i < lengthof(touching); i++)
	{
		if (strcmp(defname, touching[i]) == 0)
			return true;
	}
	return false;
}

/* The role options CREATE ROLE and ALTER ROLE share that this file tracks */
typedef struct
{
	DefElem    *dpass;
	DefElem    *dlogin;
	DefElem    *dvalid_until;
	bool		touched;
} RoleOptions;

/* Returns true when any tracked option is present */
static bool
ParseRoleOptions(List *options, RoleOptions *out)
{
	ListCell   *option;

	memset(out, 0, sizeof(*out));
	foreach(option, options)
	{
		DefElem    *defel = lfirst(option);

		if (strcmp(defel->defname, "password") == 0)
			out->dpass = defel;
		else if (strcmp(defel->defname, "canlogin") == 0)
			out->dlogin = defel;
		else if (strcmp(defel->defname, "validUntil") == 0)
			out->dvalid_until = defel;
		else if (IsTouchingRoleOption(defel->defname))
			out->touched = true;
	}
	return out->dpass || out->dlogin || out->dvalid_until || out->touched;
}

/* Records LOGIN, VALID UNTIL and touched from the statement's options */
static void
SetRoleAttributes(RoleAttrs *attrs, RoleOptions *opts)
{
	if (opts->dpass)
	{
		attrs->password = opts->dpass->arg ?
			MemoryContextStrdup(CurTransactionContext, strVal(opts->dpass->arg)) : NULL;
		attrs->password_set = true;
	}
	if (opts->dlogin)
		attrs->login_set = true;
	if (opts->dvalid_until && opts->dvalid_until->arg)
		attrs->valid_until = MemoryContextStrdup(CurTransactionContext,
												 strVal(opts->dvalid_until->arg));
	if (opts->touched)
		attrs->touched = true;
}

/*
 * After CREATE ROLE / USER / GROUP ran: the new role's OID is known. It is
 * always sent with its login and its password (an explicit null when it has
 * none), so its PASSWORD clause, if any, is kept.
 */
static void
HandleCreateRoleDone(CreateRoleStmt *stmt)
{
	RoleOptions opts;
	Oid			oid = get_role_oid(stmt->role, true);
	bool		found = false;
	RoleIdentity *id;

	if (!OidIsValid(oid))
		return;
	id = RoleIdentityFor(oid, &found);
	id->created = true;
	id->orig_name[0] = '\0';
	ParseRoleOptions(stmt->options, &opts);
	SetRoleAttributes(RoleAttrsFor(oid), &opts);
}

static void
HandleAlterRole(AlterRoleStmt *stmt)
{
	char	   *role_name;
	RoleOptions opts;
	Oid			oid;

	role_name = get_rolespec_name(stmt->role);
	if (IsPrivilegedRole(role_name) && !superuser())
		elog(ERROR, "could not ALTER %s", privileged_role_name);

	/* Return when nothing tracked is present */
	if (ParseRoleOptions(stmt->options, &opts))
	{
		oid = TouchExistingRole(role_name);
		if (OidIsValid(oid))
			SetRoleAttributes(RoleAttrsFor(oid), &opts);
	}
	pfree(role_name);
}

/* The name before the transaction is recorded; the new name is read at commit */
static void
HandleRoleRename(RenameStmt *stmt)
{
	Assert(stmt->renameType == OBJECT_ROLE);
	(void) TouchExistingRole(stmt->subname);
}

/* Likewise: a role from before the transaction that is gone at commit is sent as a del */
static void
HandleDropRole(DropRoleStmt *stmt)
{
	ListCell   *item;

	foreach(item, stmt->roles)
	{
		RoleSpec   *spec = lfirst(item);

		if (spec->roletype == ROLESPEC_CSTRING && spec->rolename)
			(void) TouchExistingRole(spec->rolename);
	}
}

static void
MarkRoleTouched(const char *role_name)
{
	Oid			oid = TouchExistingRole(role_name);

	if (OidIsValid(oid))
		RoleAttrsFor(oid)->touched = true;
}

/*
 * GRANT / REVOKE of a role: every grantee and every granted role is marked
 * touched (the receiver reads memberships from the catalog). PUBLIC isn't a
 * role and is skipped; Postgres refuses it.
 */
static void
HandleGrantRole(GrantRoleStmt *stmt)
{
	ListCell   *item;

	foreach(item, stmt->grantee_roles)
	{
		RoleSpec   *spec = lfirst(item);
		char	   *name;

		if (spec->roletype == ROLESPEC_PUBLIC)
			continue;
		name = get_rolespec_name(spec);
		MarkRoleTouched(name);
		pfree(name);
	}
	foreach(item, stmt->granted_roles)
	{
		AccessPriv *priv = lfirst(item);

		if (priv->priv_name)
			MarkRoleTouched(priv->priv_name);
	}
}


static void
HandleRename(RenameStmt *stmt)
{
	if (stmt->renameType == OBJECT_DATABASE)
		return HandleDbRename(stmt);
	else if (stmt->renameType == OBJECT_ROLE)
		return HandleRoleRename(stmt);
}


/*
 * Support for Event Triggers.
 *
 * In vanilla only superuser can create Event Triggers.
 *
 * We allow it for {privileged_role_name} by temporary switching to superuser. But as
 * far as event trigger can fire in superuser context we should protect
 * superuser from execution of arbitrary user's code.
 *
 * The idea was taken from Supabase PR series starting at
 *   https://github.com/supabase/supautils/pull/98
 */

static bool
neon_needs_fmgr_hook(Oid functionId) {

	return (next_needs_fmgr_hook && (*next_needs_fmgr_hook) (functionId))
		|| get_func_rettype(functionId) == EVENT_TRIGGEROID;
}

static void
LookupFuncOwnerSecDef(Oid functionId, Oid *funcOwner, bool *is_secdef)
{
	Form_pg_proc procForm;
	HeapTuple proc_tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(functionId));

	if (!HeapTupleIsValid(proc_tup))
		ereport(ERROR,
				(errmsg("cache lookup failed for function %u", functionId)));

	procForm = (Form_pg_proc) GETSTRUCT(proc_tup);

	*funcOwner = procForm->proowner;
	*is_secdef = procForm->prosecdef;

	ReleaseSysCache(proc_tup);
}


PG_FUNCTION_INFO_V1(noop);
Datum noop(__attribute__ ((unused)) PG_FUNCTION_ARGS) { PG_RETURN_VOID();}

static void
force_noop(FmgrInfo *finfo)
{
    finfo->fn_addr   = (PGFunction) noop;
    finfo->fn_oid    = InvalidOid;           /* not a known function OID anymore */
    finfo->fn_nargs  = 0;                    /* no arguments for noop */
    finfo->fn_strict = false;
    finfo->fn_retset = false;
    finfo->fn_stats  = 0;                    /* no stats collection */
    finfo->fn_extra  = NULL;                 /* clear out old context data */
    finfo->fn_mcxt   = CurrentMemoryContext;
    finfo->fn_expr   = NULL;                 /* no parse tree */
}


/*
 * Skip executing Event Triggers execution for superusers, because Event
 * Triggers are SECURITY DEFINER and user provided code could then attempt
 * privilege escalation.
 *
 * Also skip executing Event Triggers when GUC neon.event_triggers has been
 * set to false. This might be necessary to be able to connect again after a
 * LOGIN Event Trigger has been installed that would prevent connections as
 * {privileged_role_name}.
 */
static void
neon_fmgr_hook(FmgrHookEventType event, FmgrInfo *flinfo, Datum *private)
{
	bool		skipped = false;

	/*
	 * It can be other needs_fmgr_hook which cause our hook to be invoked for
	 * non-trigger function, so recheck that is is trigger function.
	 */
	if (flinfo->fn_oid != InvalidOid &&
		get_func_rettype(flinfo->fn_oid) != EVENT_TRIGGEROID)
	{
		if (next_fmgr_hook)
			(*next_fmgr_hook) (event, flinfo, private);

		return;
	}

	/*
	 * The {privileged_role_name} role can use the GUC neon.event_triggers to disable
	 * firing Event Trigger.
	 *
	 *   SET neon.event_triggers TO false;
	 *
	 * This only applies to the {privileged_role_name} role though, and only allows
	 * skipping Event Triggers owned by {privileged_role_name}, which we check by
	 * proxy of the Event Trigger function being owned by {privileged_role_name}.
	 *
	 * A role that is created in role {privileged_role_name} should be allowed to also
	 * benefit from the neon_event_triggers GUC, and will be considered the
	 * same as the {privileged_role_name} role.
	 */
	if (event == FHET_START
		&& !neon_event_triggers
		&& is_privileged_role())
	{
		Oid weak_superuser_oid = get_role_oid(privileged_role_name, false);

		/* Find the Function Attributes (owner Oid, security definer) */
		const char *fun_owner_name = NULL;
		Oid fun_owner = InvalidOid;
		bool fun_is_secdef = false;

		LookupFuncOwnerSecDef(flinfo->fn_oid, &fun_owner, &fun_is_secdef);
		fun_owner_name = GetUserNameFromId(fun_owner, false);

		if (IsPrivilegedRole(fun_owner_name)
			|| has_privs_of_role(fun_owner, weak_superuser_oid))
		{
			elog(WARNING,
				 "Skipping Event Trigger: neon.event_triggers is false");

			/*
			 * we can't skip execution directly inside the fmgr_hook so instead we
			 * change the event trigger function to a noop function.
			 */
			force_noop(flinfo);
			skipped = true;
		}
	}

	/*
	 * Fire Event Trigger if both function owner and current user are
	 * superuser. Allow executing Event Trigger function that belongs to a
	 * superuser when connected as a non-superuser, even when the function is
	 * SECURITY DEFINER.
	 *
	 * This check doesn't depend on neon.event_triggers: a function the check
	 * above didn't skip still goes through it.
	 */
	if (event == FHET_START
		&& !skipped
		/* still enable it to pass pg_regress tests */
		&& !RegressTestMode)
	{
		/*
		 * Check both the session user and the current user: the current user
		 * can differ from the session user (SET ROLE, SECURITY DEFINER
		 * functions, or an extension script that runs as the bootstrap
		 * superuser), and the function would run as the current user.
		 *
		 * For a SECURITY DEFINER function, fmgr has already switched the
		 * current user to the function owner when this hook runs, so the
		 * current user is the owner here, which is the role the function
		 * runs as.
		 */
		Oid session_role_oid = GetSessionUserId();
		Oid current_role_oid = GetUserId();
		Oid super_role_oid = InvalidOid;

		/* Find the Function Attributes (owner Oid, security definer) */
		Oid function_owner = InvalidOid;
		bool function_is_secdef = false;
		bool function_is_owned_by_super = false;

		if (superuser_arg(current_role_oid))
			super_role_oid = current_role_oid;
		else if (superuser_arg(session_role_oid))
			super_role_oid = session_role_oid;

		LookupFuncOwnerSecDef(flinfo->fn_oid, &function_owner, &function_is_secdef);

		function_is_owned_by_super = superuser_arg(function_owner);

		/*
		 * Refuse to run functions that belongs to a non-superuser when the
		 * session user or the current user is a superuser.
		 *
		 * We could run a SECURITY DEFINER user-function here and be safe with
		 * privilege escalation risks, but superuser roles are only used for
		 * infrastructure maintenance operations, where we prefer to skip
		 * running user-defined code.
		 *
		 * Note: a SECURITY DEFINER function owned by a non-superuser still
		 * runs, as its owner and with no privilege gain, when only the
		 * caller's current user is a superuser (the current user is the
		 * owner while the function runs).
		 */
		if (OidIsValid(super_role_oid) && !function_is_owned_by_super)
		{
			char *func_name = get_func_name(flinfo->fn_oid);

			ereport(WARNING,
					(errmsg("Skipping Event Trigger"),
					 errdetail("Event Trigger function \"%s\" "
							   "is owned by non-superuser role \"%s\", "
							   "and %s \"%s\" is superuser",
							   func_name,
							   GetUserNameFromId(function_owner, false),
							   super_role_oid == current_role_oid
							   ? "current_user" : "session_user",
							   GetUserNameFromId(super_role_oid, false))));

			/*
			 * we can't skip execution directly inside the fmgr_hook so
			 * instead we change the event trigger function to a noop
			 * function.
			 */
			force_noop(flinfo);
		}
	}

	if (next_fmgr_hook)
		(*next_fmgr_hook) (event, flinfo, private);
}

static Oid prev_role_oid = 0;
static int prev_role_sec_context = 0;
static bool switched_to_superuser = false;

/*
 * Switch tp superuser if not yet superuser.
 * Returns false if already switched to superuser.
 */
static bool
switch_to_superuser(void)
{
    Oid superuser_oid;

	if (switched_to_superuser)
		return false;
	switched_to_superuser = true;

	superuser_oid = get_role_oid("cloud_admin", true /*missing_ok*/);
	if (superuser_oid == InvalidOid)
		superuser_oid = BOOTSTRAP_SUPERUSERID;

    GetUserIdAndSecContext(&prev_role_oid, &prev_role_sec_context);
    SetUserIdAndSecContext(superuser_oid, prev_role_sec_context |
                                              SECURITY_LOCAL_USERID_CHANGE |
                                              SECURITY_RESTRICTED_OPERATION);
	return true;
}

static void
switch_to_original_role(void)
{
    SetUserIdAndSecContext(prev_role_oid, prev_role_sec_context);
    switched_to_superuser = false;
}

/*
 * ALTER ROLE ... SUPERUSER;
 *
 * Used internally to give superuser to a non-privileged role to allow
 * ownership of superuser-only objects such as Event Trigger.
 *
 *   ALTER ROLE foo SUPERUSER;
 *   ALTER EVENT TRIGGER ... OWNED BY foo;
 *   ALTER ROLE foo NOSUPERUSER;
 *
 * Now the EVENT TRIGGER is owned by foo, who can DROP it without having to be
 * superuser again.
 */
static void
alter_role_super(const char* rolename, bool make_super)
{
	AlterRoleStmt *alter_stmt = makeNode(AlterRoleStmt);

	DefElem *defel_superuser =
#if PG_MAJORVERSION_NUM <= 14
		makeDefElem("superuser", (Node *) makeInteger(make_super), -1);
#else
		makeDefElem("superuser", (Node *) makeBoolean(make_super), -1);
#endif

	RoleSpec *rolespec   = makeNode(RoleSpec);
	rolespec->roletype   = ROLESPEC_CSTRING;
	rolespec->rolename   = pstrdup(rolename);
	rolespec->location   = -1;

	alter_stmt->role = rolespec;
	alter_stmt->options = list_make1(defel_superuser);

#if PG_MAJORVERSION_NUM < 15
	AlterRole(alter_stmt);
#else
	/* ParseState *pstate, AlterRoleStmt *stmt */
	AlterRole(NULL, alter_stmt);
#endif

	CommandCounterIncrement();
}


/*
 * Changes the OWNER of an Event Trigger.
 *
 * Event Triggers can only be owned by superusers, so this ALTER ROLE with
 * SUPERUSER and then removes the property.
 */
static void
alter_event_trigger_owner(const char *obj_name, Oid role_oid)
{
	char* role_name = GetUserNameFromId(role_oid, false);

	alter_role_super(role_name, true);

	AlterEventTriggerOwner(obj_name, role_oid);
	CommandCounterIncrement();

	alter_role_super(role_name, false);
}


/*
 * Neon processing of the CREATE EVENT TRIGGER requires special attention and
 * is worth having its own ProcessUtility_hook for that.
 */
static void
ProcessCreateEventTrigger(
				   PlannedStmt *pstmt,
				   const char *queryString,
				   bool readOnlyTree,
				   ProcessUtilityContext context,
				   ParamListInfo params,
				   QueryEnvironment *queryEnv,
				   DestReceiver *dest,
				   QueryCompletion *qc)
{
	Node	   *parseTree = pstmt->utilityStmt;
	bool		sudo = false;

	/* We double-check that after local variable declaration block */
	CreateEventTrigStmt *stmt = (CreateEventTrigStmt *) parseTree;

	/*
	 * We are going to change the current user privileges (sudo) and might
	 * need after execution cleanup. For that we want to capture the UserId
	 * before changing it for our sudo implementation.
	 */
	const Oid current_user_id = GetUserId();
	bool current_user_is_super = superuser_arg(current_user_id);

	if (nodeTag(parseTree) != T_CreateEventTrigStmt)
	{
		ereport(ERROR,
				errcode(ERRCODE_INTERNAL_ERROR),
				errmsg("ProcessCreateEventTrigger called for the wrong command"));
	}

	/*
	 * Allow {privileged_role_name} to create Event Trigger, while keeping the
	 * ownership of the object.
	 *
	 * For that we give superuser membership to the role for the execution of
	 * the command.
	 */
	if (IsTransactionState() && is_privileged_role())
	{
		/* Find the Event Trigger function Oid */
		Oid func_oid = LookupFuncName(stmt->funcname, 0, NULL, false);

		/* Find the Function Owner Oid */
		Oid func_owner = InvalidOid;
		bool is_secdef = false;
		bool function_is_owned_by_super = false;

		LookupFuncOwnerSecDef(func_oid, &func_owner, &is_secdef);

		function_is_owned_by_super = superuser_arg(func_owner);

		if(!current_user_is_super && function_is_owned_by_super)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("Permission denied to execute "
							"a function owned by a superuser role"),
					 errdetail("current user \"%s\" is not a superuser "
							   "and Event Trigger function \"%s\" "
							   "is owned by a superuser",
							   GetUserNameFromId(current_user_id, false),
							   NameListToString(stmt->funcname))));
		}

		if(current_user_is_super && !function_is_owned_by_super)
		{
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("Permission denied to execute "
							"a function owned by a non-superuser role"),
					 errdetail("current user \"%s\" is a superuser "
							   "and function \"%s\" is "
							   "owned by a non-superuser",
							   GetUserNameFromId(current_user_id, false),
							   NameListToString(stmt->funcname))));
		}

		sudo = switch_to_superuser();
	}

	PG_TRY();
	{
		if (PreviousProcessUtilityHook)
		{
			PreviousProcessUtilityHook(
				pstmt,
				queryString,
				readOnlyTree,
				context,
				params,
				queryEnv,
				dest,
				qc);
		}
		else
		{
			standard_ProcessUtility(
				pstmt,
				queryString,
				readOnlyTree,
				context,
				params,
				queryEnv,
				dest,
				qc);
		}

		/*
		 * Now that the Event Trigger has been installed via our sudo
		 * mechanism, if the original role was not a superuser then change
		 * the event trigger ownership back to the original role.
		 *
		 * That way [ ALTER | DROP ] EVENT TRIGGER commands just work.
		 */
		if (IsTransactionState() && is_privileged_role())
		{
			if (!current_user_is_super)
			{
				/*
				 * Change event trigger owner to the current role (making
				 * it a privileged role during the ALTER OWNER command).
				 */
				alter_event_trigger_owner(stmt->trigname, current_user_id);
			}
		}
	}
	PG_FINALLY();
	{
		if (sudo)
			switch_to_original_role();
	}
	PG_END_TRY();
}


/*
 * Is "dbname" listed in neon.protected_databases (comma-separated, matched
 * exactly, no case folding)?
 */
static bool
IsProtectedDatabase(const char *dbname)
{
	char	   *list;
	char	   *cur;
	bool		found = false;

	if (ProtectedDatabases == NULL || ProtectedDatabases[0] == '\0')
		return false;

	list = pstrdup(ProtectedDatabases);
	cur = list;
	while (cur != NULL && !found)
	{
		char	   *end = strchr(cur, ',');

		if (end != NULL)
			*end++ = '\0';
		while (*cur == ' ' || *cur == '\t')
			cur++;
		for (char *tail = cur + strlen(cur); tail > cur && (tail[-1] == ' ' || tail[-1] == '\t'); tail--)
			tail[-1] = '\0';
		found = (cur[0] != '\0' && strcmp(cur, dbname) == 0);
		cur = end;
	}
	pfree(list);
	return found;
}

/*
 * Neon hooks for DDLs (handling privileges, limiting features, etc).
 */
static void
NeonProcessUtility(
				   PlannedStmt *pstmt,
				   const char *queryString,
				   bool readOnlyTree,
				   ProcessUtilityContext context,
				   ParamListInfo params,
				   QueryEnvironment *queryEnv,
				   DestReceiver *dest,
				   QueryCompletion *qc)
{
	Node	   *parseTree = pstmt->utilityStmt;

	/*
	 * Refuse to drop a protected database. This runs first, before any early
	 * return below and before the statement itself, so the database is left
	 * valid and its files untouched. Superusers can still drop it.
	 */
	if (IsA(parseTree, DropdbStmt))
	{
		DropdbStmt *dropstmt = castNode(DropdbStmt, parseTree);

		if (IsProtectedDatabase(dropstmt->dbname) && !superuser())
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
					 errmsg("the branch's main database \"%s\" can't be dropped",
							dropstmt->dbname)));
	}

	/*
	 * The process utility hook for CREATE EVENT TRIGGER is its own
	 * implementation and warrant being addressed separately from here.
	 */
	if (nodeTag(parseTree) == T_CreateEventTrigStmt)
	{
		ProcessCreateEventTrigger(
				pstmt,
				queryString,
				readOnlyTree,
				context,
				params,
				queryEnv,
				dest,
				qc);
		return;
	}

	/*
	 * Other commands that need Neon specific implementations are handled here:
	 */
	switch (nodeTag(parseTree))
	{
		case T_CreatedbStmt:
			HandleCreateDb(castNode(CreatedbStmt, parseTree));
			break;
		case T_AlterOwnerStmt:
			HandleAlterOwner(castNode(AlterOwnerStmt, parseTree));
			break;
		case T_RenameStmt:
			HandleRename(castNode(RenameStmt, parseTree));
			break;
		case T_DropdbStmt:
			HandleDropDb(castNode(DropdbStmt, parseTree));
			break;
		case T_AlterRoleStmt:
			HandleAlterRole(castNode(AlterRoleStmt, parseTree));
			break;
		case T_DropRoleStmt:
			HandleDropRole(castNode(DropRoleStmt, parseTree));
			break;
		case T_GrantRoleStmt:
			HandleGrantRole(castNode(GrantRoleStmt, parseTree));
			break;
		case T_CreateTableSpaceStmt:
			if (!RegressTestMode)
			{
				ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					errmsg("CREATE TABLESPACE is not supported on Neon")));
			}
   			break;
		default:
			break;
	}

	if (PreviousProcessUtilityHook)
	{
		PreviousProcessUtilityHook(
			pstmt,
			queryString,
			readOnlyTree,
			context,
			params,
			queryEnv,
			dest,
			qc);
	}
	else
	{
		standard_ProcessUtility(
			pstmt,
			queryString,
			readOnlyTree,
			context,
			params,
			queryEnv,
			dest,
			qc);
	}

	/* A new role is tracked once it exists (by its OID) */
	if (IsA(parseTree, CreateRoleStmt))
		HandleCreateRoleDone(castNode(CreateRoleStmt, parseTree));
}

/*
 * Only {privileged_role_name} is granted privilege to edit neon.event_triggers GUC.
 */
static void
neon_event_triggers_assign_hook(bool newval, void *extra)
{
	if (IsTransactionState() && !is_privileged_role())
	{
		ereport(ERROR,
				(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
				 errmsg("permission denied to set neon.event_triggers"),
				 errdetail("Only \"%s\" is allowed to set the GUC", privileged_role_name)));
	}
}


void
InitDDLHandler()
{
	PreviousProcessUtilityHook = ProcessUtility_hook;
	ProcessUtility_hook = NeonProcessUtility;

    next_needs_fmgr_hook = needs_fmgr_hook;
	needs_fmgr_hook = neon_needs_fmgr_hook;

	next_fmgr_hook = fmgr_hook;
	fmgr_hook = neon_fmgr_hook;

	RegisterXactCallback(NeonXactCallback, NULL);
	RegisterSubXactCallback(NeonSubXactCallback, NULL);

	/*
	 * The GUC neon.event_triggers should provide the same effect as the
	 * Postgres GUC event_triggers, but the neon one is PGC_USERSET.
	 *
	 * This allows using the GUC in the connection string and work out of a
	 * LOGIN Event Trigger that would break database access, all without
	 * having to edit and reload the Postgres configuration file.
	 */
	DefineCustomBoolVariable(
							 "neon.event_triggers",
							 "Enable firing of event triggers",
							 NULL,
							 &neon_event_triggers,
							 true,
							 PGC_USERSET,
							 0,
							 NULL,
							 neon_event_triggers_assign_hook,
							 NULL);

	DefineCustomStringVariable(
							   "neon.console_url",
							   "URL of the Neon Console, which will be forwarded changes to dbs and roles",
							   NULL,
							   &ConsoleURL,
							   NULL,
							   PGC_POSTMASTER,
							   0,
							   NULL,
							   NULL,
							   NULL);

	DefineCustomStringVariable(
							   "neon.protected_databases",
							   "Databases that only a superuser can drop: exact names, comma-separated, whitespace trimmed",
							   NULL,
							   &ProtectedDatabases,
							   "",
							   PGC_SUSET,
							   0,
							   NULL,
							   NULL,
							   NULL);

	DefineCustomBoolVariable(
							 "neon.forward_ddl",
							 "Controls whether to forward DDL to the control plane",
							 NULL,
							 &ForwardDDL,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable(
							 "neon.regress_test_mode",
							 "Controls whether we are running in the regression test mode",
							 NULL,
							 &RegressTestMode,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	jwt_token = getenv("NEON_CONTROL_PLANE_TOKEN");
	if (!jwt_token)
	{
		elog(LOG, "Missing NEON_CONTROL_PLANE_TOKEN environment variable, forwarding will not be authenticated");
	}

}
