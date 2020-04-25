DESCRIPTION = LDAP Authentication Helper Library
URL = https://github.com/ikle/ldap-auth

LIBNAME	= ldap-auth
LIBVER	= 0
LIBREV	= 0.1

LDFLAGS += -lldap

include make-core.mk
