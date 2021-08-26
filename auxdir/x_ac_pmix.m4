##*****************************************************************************
#  AUTHOR:
#    Artem Polyakov <artpol84@gmail.com>
#    Ralph Castain <ralph.h.castain@intel.com>
#
#  SYNOPSIS:
#    X_AC_PMIX
#
#  DESCRIPTION:
#    Determine if the PMIx libraries exists. Derived from "x_ac_hwloc.m4".
##*****************************************************************************

AC_DEFUN([X_AC_PMIX],
[
  _x_ac_pmix_dirs="/usr /usr/local"
  _x_ac_pmix_libs="lib64 lib"

  _x_ac_pmix_found="0"

  AC_ARG_WITH(
    [pmix],
    AS_HELP_STRING(--with-pmix=PATH,Specify path to pmix installation(s).  Multiple version directories can be ':' delimited.),
    [AS_IF([test "x$with_pmix" != xno && test "x$with_pmix" != xyes],
           [_x_ac_pmix_dirs="`echo $with_pmix | sed "s/:/ /g"`"])])

  if [test "x$with_pmix" = xno]; then
    AC_MSG_WARN([support for pmix disabled])
  else
    AC_CACHE_CHECK(
      [for pmix installation],
      [x_ac_cv_pmix_dir],
      [
        for d in $_x_ac_pmix_dirs; do
          if [ ! test -d "$d/include" ] || [ ! test -f "$d/include/pmix_server.h" ] ||
		[ ! test -f "$d/include/pmix/pmix_common.h" && ! test -f $d/include/pmix_common.h ]; then
		if [ test -n "$with_pmix" && test "$with_pmix" != yes ]; then
			AC_MSG_ERROR([No PMIX installation found in $d])
		fi
		continue
	  fi
          for d1 in $_x_ac_pmix_libs; do
            test -d "$d/$d1" || continue
            _x_ac_pmix_cppflags_save="$CPPFLAGS"
            CPPFLAGS="-I$d/include $CPPFLAGS"
            _x_ac_pmix_libs_save="$LIBS"
            LIBS="-L$d/$d1 -lpmix $LIBS"
            AC_LINK_IFELSE(
              [AC_LANG_CALL([], PMIx_Get_version)],
              AS_VAR_SET(x_ac_cv_pmix_dir, $d)
              AS_VAR_SET(x_ac_cv_pmix_libdir, $d/$d1))

            if [test -z "$x_ac_cv_pmix_dir"] ||
               [test -z "$x_ac_cv_pmix_libdir"]; then
              AC_MSG_WARN([unable to locate pmix installation])
              continue
            fi

            CPPFLAGS="$_x_ac_pmix_cppflags_save"
            LIBS="$_x_ac_pmix_libs_save"

            m4_define([err_pmix],[was already found in one of the previous paths])

              _x_ac_pmix_found="1"
              PMIX_CPPFLAGS="-I$x_ac_cv_pmix_dir/include -DPMIXP_LIBPATH=\\\"$x_ac_cv_pmix_libdir\\\""
              if test "$ac_with_rpath" = "yes"; then
                PMIX_LDFLAGS="-Wl,-rpath -Wl,$x_ac_cv_pmix_libdir -L$x_ac_cv_pmix_libdir"
              fi
              # We don't want to search the other lib after we found it in
              # one place or we might report a false duplicate if lib64 is a
              # symlink of lib.
              break

          done
        done
      ])

    AC_DEFINE(HAVE_PMIX, 1, [Define to 1 if pmix library found])

    AC_SUBST(PMIX_CPPFLAGS)
    AC_SUBST(PMIX_LDFLAGS)

    if test $_x_ac_pmix_found = 0 ; then
      if test -z "$with_pmix"; then
        AC_MSG_WARN([unable to locate pmix installation])
      else
        AC_MSG_ERROR([unable to locate pmix installation])
      fi
    fi
  fi

  AM_CONDITIONAL(HAVE_PMIX, [test $_x_ac_pmix_found = "1"])
])
