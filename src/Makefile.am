ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = meer
                               meer_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       meer_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               meer_SOURCES = meer.c 

                                                       install-data-local:

