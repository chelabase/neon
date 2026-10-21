/*-------------------------------------------------------------------------
 *
 * extension_server.c
 *	  Request compute_ctl to download extension files.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <curl/curl.h>

#include "utils/guc.h"

#include "extension_server.h"
#include "neon_utils.h"
#include "token_file.h"

int	hadron_extension_server_port = 0;
static int	extension_server_request_timeout = 60;
static int	extension_server_connect_timeout = 60;

static download_extension_file_hook_type prev_download_extension_file_hook = NULL;

/*
  * to download all SQL (and data) files for an extension:
  * curl -X POST -H "Authorization: Bearer <secret>" http://127.0.0.1:8080/extension_server/postgis
  * it covers two possible extension files layouts:
  * 1. extension_name--version--platform.sql
  * 2. extension_name/extension_name--version.sql
  *    extension_name/extra_files.csv
  * to download specific library file:
  * curl -X POST -H "Authorization: Bearer <secret>" http://127.0.0.1:8080/extension_server/postgis-3.so?is_library=true
  */
static bool
neon_download_extension_file_http(const char *filename, bool is_library)
{
	CURLcode	res;
	long		http_code = 0;
	CURL	   *handle;
	struct curl_slist *headers;
	char	   *compute_ctl_url;
	char	   *escaped;
	int			url_len;

	/*
	 * alloc_curl_handle() may throw, so it comes first, before anything is
	 * held.  From here to the cleanup nothing may throw: the handle, the
	 * escaped name (malloc'd) and the header list are freed on every path.
	 */
	handle = alloc_curl_handle();

	/*
	 * The name is the session's (CREATE EXTENSION's name, LOAD's library):
	 * percent-encode it so it stays one path segment, and "?", "#", "%", "&"
	 * or "/" in it never become a query string, a fragment, an escape or
	 * another path.  curl_easy_escape keeps only [A-Za-z0-9._~-] as they are,
	 * so an ordinary name is unchanged.
	 */
	escaped = curl_easy_escape(handle, filename, 0);
	if (escaped == NULL)
	{
		curl_easy_cleanup(handle);
		elog(WARNING, "neon_download_extension_file_http failed: could not escape the file name");
		return false;
	}

	/*
	 * compute_ctl's internal server listens on loopback only, and wants the
	 * internal API secret, read from its file before every call (a missing
	 * or invalid file means no header, and compute_ctl refuses the call).
	 */
#define EXTENSION_SERVER_URL_FORMAT "http://127.0.0.1:%d/extension_server/%s%s"
	url_len = snprintf(NULL, 0, EXTENSION_SERVER_URL_FORMAT,
					   hadron_extension_server_port, escaped,
					   is_library ? "?is_library=true" : "");
	compute_ctl_url = url_len < 0 ? NULL :
		palloc_extended(url_len + 1, MCXT_ALLOC_NO_OOM);
	if (compute_ctl_url == NULL)
	{
		curl_free(escaped);
		curl_easy_cleanup(handle);
		elog(WARNING, "neon_download_extension_file_http failed: out of memory");
		return false;
	}
	snprintf(compute_ctl_url, url_len + 1, EXTENSION_SERVER_URL_FORMAT,
			 hadron_extension_server_port, escaped,
			 is_library ? "?is_library=true" : "");
#undef EXTENSION_SERVER_URL_FORMAT
	curl_free(escaped);

	headers = neon_compute_ctl_auth_headers();

	curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "POST");
	if (extension_server_request_timeout > 0)
		curl_easy_setopt(handle, CURLOPT_TIMEOUT, (long)extension_server_request_timeout /* seconds */ );
	if (extension_server_connect_timeout > 0)
		curl_easy_setopt(handle, CURLOPT_CONNECTTIMEOUT, (long)extension_server_connect_timeout /* seconds */ );
	curl_easy_setopt(handle, CURLOPT_URL, compute_ctl_url);
	curl_easy_setopt(handle, CURLOPT_HTTPHEADER, headers);

	/* Perform the request, res will get the return code */
	res = curl_easy_perform(handle);
	if (res == CURLE_OK)
		res = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
	curl_easy_cleanup(handle);
	curl_slist_free_all(headers);

	elog(LOG, "Requested from compute_ctl: %s", compute_ctl_url);

	/*
	 * Don't error here because postgres will try to find the file and will
	 * fail with some proper error message if it's not found.
	 */
	if (res != CURLE_OK)
	{
		elog(WARNING, "neon_download_extension_file_http failed: %s", curl_easy_strerror(res));
		pfree(compute_ctl_url);
		return false;
	}
	if (http_code < 200 || http_code > 299)
	{
		elog(WARNING, "neon_download_extension_file_http failed: compute_ctl answered HTTP %ld to %s",
			 http_code, compute_ctl_url);
		pfree(compute_ctl_url);
		return false;
	}

	pfree(compute_ctl_url);
	return true;
}

void
pg_init_extension_server()
{
	/*
	 * The port of compute_ctl's internal server on 127.0.0.1, for extension
	 * downloads and refresh_configuration.
	 */
	DefineCustomIntVariable("neon.extension_server_port",
							"connection string to the compute_ctl",
							NULL,
							&hadron_extension_server_port,
							0, 0, INT_MAX,
							PGC_POSTMASTER,
							0,	/* no flags required */
							NULL, NULL, NULL);

	DefineCustomIntVariable("neon.extension_server_request_timeout",
							"timeout for fetching extensions in seconds",
							NULL,
							&extension_server_request_timeout,
							60, 0, INT_MAX,
							PGC_SUSET,
							GUC_UNIT_S,
							NULL, NULL, NULL);

	DefineCustomIntVariable("neon.extension_server_connect_timeout",
							"timeout for connecting to the extension server in seconds",
							NULL,
							&extension_server_connect_timeout,
							60, 0, INT_MAX,
							PGC_SUSET,
							GUC_UNIT_S,
							NULL, NULL, NULL);

	/* set download_extension_file_hook */
	prev_download_extension_file_hook = download_extension_file_hook;
	download_extension_file_hook = neon_download_extension_file_http;
}
