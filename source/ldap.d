module ldap;

import std.stdio;
import std.format : format;
import std.exception : enforce;
import std.string : fromStringz;

import ldapd;

private void tool_unbind_local(LDAP *ld) @trusted {
	int err = ldap_set_option(ld, LDAP_OPT_SERVER_CONTROLS, null);

	if(err != LDAP_OPT_SUCCESS) {
		throw new Exception("Could not unset controls");
	}

	ldap_unbind_ext( ld, null, null );
}

private int tool_exit_local( LDAP *ld, int status ) @trusted {
	if(ld != null) {
		tool_unbind_local(ld);
	}
	return status;
}

private LDAP* tool_conn_setup_local(char* lhost, int lport ) @trusted {
	LDAP *ld = null;

	int rc;
	char *ldapuri;

	scope(exit) {
		ldap_memfree(ldapuri);
	}

	//if( ( lhost != null || lport ) && ( ldapuri == null ) ) {
	assert(lhost !is null && lport );
	/* construct URL */
	LDAPURLDesc url;

	url.lud_scheme = cast(char*)"ldap".ptr;
	url.lud_host = lhost;
	url.lud_port = lport;
	url.lud_scope = LDAP_SCOPE_DEFAULT;

	ldapuri = ldap_url_desc2str(&url);

	//writefln("ldap_initialize( %s )", ldapuri !is null ? ldapuri : "<DEFAULT>" );

	// BUG
	// BUG ldap_initialize leaks 40 byte of memory
	// BUG
	rc = ldap_initialize(&ld, ldapuri);

	if(rc != LDAP_SUCCESS) {
		throw new Exception(format(
			"Could not create LDAP session handle for URI=%s (%d): %s",
			ldapuri, rc, ldap_err2string(rc)));
	}

	/* referrals: obsolete */
	if(ldap_set_option(ld, LDAP_OPT_REFERRALS, LDAP_OPT_ON) != LDAP_OPT_SUCCESS) {
		throw new Exception(format("Could not set LDAP_OPT_REFERRALS on"));
	}

	int lprotocol = LDAP_VERSION3;
	if(ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &lprotocol)
		!= LDAP_OPT_SUCCESS )
	{
		throw new Exception(format("Could not set LDAP_OPT_PROTOCOL_VERSION %d",
			lprotocol) );
	}

	rc = ldap_start_tls_s( ld, null, null );
	if(rc != LDAP_SUCCESS) {
		char* msg;
		scope(exit) {
			ldap_memfree(msg);
		}
		ldap_get_option(ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &msg);
		throw new Exception(
				format("ldap_start_tls %d %s", rc, fromStringz(msg).idup));
	}

	timeval nettimeout;
	if(nettimeout.tv_sec > 0) {
		if(ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &nettimeout)
			!= LDAP_OPT_SUCCESS)
		{
			throw new Exception(format("Could not set LDAP_OPT_NETWORK_TIMEOUT %s",
				cast(long)nettimeout.tv_sec));
		}
	}

	return ld;
}

private int tool_exit(LDAP *ld, int status) @trusted {
	if(ld !is null) {
		tool_unbind_local(ld);
	}
	return status;
}

private int tool_bind_local(LDAP *ld, char* passLocal, char* binddn) @trusted {
	LDAPControl	**sctrlsp;
	LDAPControl[4] *sctrls;
	int	nsctrls = 0;

	int rc;
	int msgid;
	LDAPMessage *result;

	int err;
	char *matched;
	char *info;
	char **refs;
	LDAPControl **ctrls;
	char[256] msgbuf;

	msgbuf[0] = 0;

	if(nsctrls) {
		sctrlsp = cast(LDAPControl**)sctrls.ptr;
	}

	//assert( nsctrls < cast(int) (sctrls.sizeof / sctrls[0].sizeof) );

	char *pw = passLocal;

	berval passwd;
	passwd.bv_val = ber_strdup(pw);
	passwd.bv_len = strlen(passwd.bv_val);

	scope(exit) {
		ber_memfree(passwd.bv_val);
		ber_memfree(matched);
		ber_memfree(info);
		ber_memvfree(cast(void **)refs);
	}

	/* simple bind */
	rc = ldap_sasl_bind(ld, binddn, LDAP_SASL_SIMPLE, &passwd,
		sctrlsp, null, &msgid);
	if(msgid == -1) {
		tool_exit(ld, rc);
		throw new Exception(format("ldap_sasl_bind: %s (code: 0x%x)", fromStringz(ldap_err2string(rc)), rc));
	}

	scope(failure) {
		tool_exit(ld, LDAP_LOCAL_ERROR);
	}

	rc = ldap_result(ld, msgid, LDAP_MSG_ALL, null, &result);
	enforce(rc != -1, format("ldap_result %d", -1));
	enforce(rc != 0, format("ldap_result %d", LDAP_TIMEOUT));

	if(result) {
		rc = ldap_parse_result( ld, result, &err, &matched, &info, &refs,
		                        &ctrls, 1 );
		if(rc != LDAP_SUCCESS) {
			return tool_exit(ld, LDAP_LOCAL_ERROR);
		}
	}

	if(err != LDAP_SUCCESS
		|| msgbuf[0]
		|| (matched && matched[ 0 ])
		|| (info && info[ 0 ])
		|| refs)
	{
		if(err != LDAP_SUCCESS) {
			return tool_exit(ld, err);
		}
	}
	return 0;
}

/*
int main(string[] args) {
	string un = "testuser@host.com";
	string pwd = "$ymm3try86!";

	string host = "ad.host.com";
	LDAPLoginResult ret = login(host, un, pwd);
	writeln(ret);
	return ret.returnCode;
}*/

struct LDAPLoginResult {
	int returnCode;
	string userId;
}

LDAPLoginResult login(string host, string username, string password) @trusted {
	import std.string : toStringz;
	import std.conv : to;
	int	rc;
	LDAP* ld;
	char* matcheddn;
	char* text;
	char** refs;
	berval* authzid;
	int	id;
	int code = 0;
	LDAPMessage* res;
	LDAPControl** ctrls;

	char* binddn = ber_strdup(toStringz(username));
	char* ldaphost = ber_strdup(toStringz(host));

	scope(exit) {
		ldap_msgfree(res);
		ber_memfree(text);
		ber_memfree(matcheddn);
		ber_memvfree(cast(void **) refs);
		ber_bvfree(authzid);
		ber_memfree(binddn);
		ber_memfree(ldaphost);
	}

	/* LDAPv3 only */

	ld = tool_conn_setup_local(ldaphost, 389);
	enforce(ld != null, format("Failed to connect to LDAP server"));

	int ret = tool_bind_local( ld, cast(char*)toStringz(password), binddn);

	enforce(ret == LDAP_SUCCESS, format("LDAP bind failed: %s (code: 0x%x)", fromStringz(ldap_err2string(ret)), ret));

	rc = ldap_whoami( ld, null, null, &id );

	enforce(ret == LDAP_SUCCESS, format("ldap_whoami failed: %s (code: 0x%x)", fromStringz(ldap_err2string(rc)), rc));

	for( ; ; ) {
		scope(failure) {
			rc = tool_exit_local( ld, rc );
		}

		timeval tv;

		tv.tv_sec = 0;
		tv.tv_usec = 100000;

		rc = ldap_result( ld, LDAP_RES_ANY, LDAP_MSG_ALL, &tv, &res );
		enforce(rc >= 0, format("ldap_result: %s (code: 0x%x)", fromStringz(ldap_err2string(rc)), rc));

		if(rc != 0) {
			break;
		}
	}

	rc = ldap_parse_result( ld, res,
		&code, &matcheddn, &text, &refs, &ctrls, 0 );

	if(rc == LDAP_SUCCESS) {
		rc = code;
	}

	enforce(rc == LDAP_SUCCESS, format("ldap_parse_result: %s (code: 0x%x)", fromStringz(ldap_err2string(rc)), rc));

	rc = ldap_parse_whoami( ld, res, &authzid );
	enforce(rc == LDAP_SUCCESS, format("ldap_parse_whoami: %s (code: 0x%x)", fromStringz(ldap_err2string(rc)), rc));

	LDAPLoginResult rslt;
	if(authzid != null) {
		if(authzid.bv_len == 0) {
			rslt.userId = "anonymous";
		} else {
			rslt.userId = to!string(fromStringz(authzid.bv_val));
		}
	}

	/* disconnect from server */
	rslt.returnCode = tool_exit_local(ld, code == LDAP_SUCCESS ? 0 : 1 );
	return rslt;
}
