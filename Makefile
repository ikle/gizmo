DESCRIPTION = LDAP Access Helper Library
URL = https://github.com/ikle/gizmo

LIBNAME	= gizmo
LIBVER	= 0
LIBREV	= 0.4

LDFLAGS += -llber -lldap

include make-core.mk
