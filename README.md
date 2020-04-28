# LDAP Authentication Helper Library

## Required options

*  uri — shema://[host[:port]], where the schema is one from ldap, ldaps
   (LDAP over TLS) or ldapi (LDAP over IPC).
*  userdn — the DN of the entry at which to start the search of user nodes.

## Authentication on LDAP server

The login service required to search user and group nodes and read it's
attributes. To authenticate login service on LDAP server specify user and
password options:

*  user — login service DN for simple authentication;
*  password — login service password for simple authentication.

If user is not specified, then anonymous login for login service will be used.
If user option provided, but password is not, then empty password assumed.

## The user node configuration

We are support the next types of user node specification:

*  Generic: users are searched by common name (CN) attribute and must belong
   to person class;
*  POSIX: users are searched by uid attribute and must belong to posixAccount
   class;
*  Active Directory: users are searched by sAMAccountName attribute and must
   belong to User class.

## Restrict login to selected user group

To authorize users who are members of only a specific group or role, specify
next two options:

*  role — common name (CN) of a group or a role to which user must belong
   to log in;
*  roledn — the DN of the entry at which to start the search of group or
   role nodes.

We are support the next classes of groups or roles:

*  Group: user DN must be specified as one of member attribute;
*  groupOfUniqueNames: user DN must be specified as one of uniqueMember;
*  organizationalRole: user DN must be specified as one of roleOccupant.

## Transport Layer Security

To use TLS either use LDAPS, or specify tls field with the value from next
list:

*  never — do not request or check any server certificate;
*  allow — request server certificate and if no certificate is provided or
   a bad certificate is provided, the session proceeds normally;
*  try — request server certificate and if no certificate is provided, the
   session proceeds normally, but if a bad certificate is provided, the
   session is immediately terminated;
*  demand — request server certificate and if no certificate is provided or
   a bad certificate is provided, the session is immediately terminated.

It is always recommended to use TLS and use it in demand mode.

Optional TLS filelds:

*  cadir — the path of the directory containing CA certificate;
*  ca — the full-path of the CA certificate file;
*  cert — the full-path of the client certificate file;
*  key — the full-path of the client certificate key file.
