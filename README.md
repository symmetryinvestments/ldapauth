# ldap

Use this to authenticate a username with password against a hostname that is
either a ldap or active directory.

Uses tls if possible so you don't send people's password in clear text.

This is a tiny lib to mimic the ldap util *whoami*.
The only function you should be required to use is:
```D
LDAPLoginResult login(string host, string username, string password);
```
The function will throw if the login fails for whatever reason.

On success the LDAPLoginResult will contain the userId inside the ldap/active
directory.

The returnCode stored in the LDAPLoginResult will be 0 on success.

## TLS

Properly using tls/ssl to connect to ldap or active directory is required but
not as easy as it should.
Especially, if the active directory is configured creatively.

**Before you put this into production test with wireshark or similar that TLS
works.**
