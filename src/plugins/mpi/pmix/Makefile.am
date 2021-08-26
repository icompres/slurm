# Makefile for mpi/pmix plugin

AUTOMAKE_OPTIONS = foreign

PLUGIN_FLAGS = -module -avoid-version --export-dynamic

AM_CPPFLAGS = -DSLURM_PLUGIN_DEBUG -I$(top_srcdir) -I$(top_srcdir)/src/common $(HWLOC_CPPFLAGS) \
	$(UCX_CPPFLAGS)

pmix_src = \
	mapping.c mapping.h \
	mpi_pmix.c \
	pmixp_common.h pmixp_coll.h \
	pmixp_agent.c pmixp_client.c pmixp_nspaces.c pmixp_info.c \
	pmixp_agent.h pmixp_client.h pmixp_nspaces.h pmixp_info.h \
	pmixp_server.c pmixp_state.c pmixp_io.c pmixp_utils.c pmixp_dmdx.c \
	pmixp_server.h pmixp_state.h pmixp_io.h pmixp_utils.h pmixp_dmdx.h \
	pmixp_conn.c pmixp_dconn.c pmixp_dconn_tcp.c \
	pmixp_conn.h pmixp_dconn.h pmixp_dconn_tcp.h \
	pmixp_coll.c pmixp_coll_tree.c pmixp_coll_ring.c

if HAVE_UCX
pmix_src += pmixp_dconn_ucx.c pmixp_dconn_ucx.h
endif

pmix_ldflags = $(PLUGIN_FLAGS) $(HWLOC_LDFLAGS) $(UCX_LDFLAGS)
pmix_libadd = $(HWLOC_LIBS) $(UCX_LIBS)

pkglib_dir=$(pkglibdir)
pkglib_LTLIBRARIES = mpi_pmix.la
mpi_pmix_la_SOURCES = $(pmix_src) pmixp_client_v2.c
mpi_pmix_la_LIBADD = $(pmix_libadd)
mpi_pmix_la_LDFLAGS = $(pmix_ldflags) $(PMIX_LDFLAGS)
mpi_pmix_la_CPPFLAGS = $(AM_CPPFLAGS) $(PMIX_CPPFLAGS)
