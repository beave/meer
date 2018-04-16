ACLOCAL_AMFLAGS = -I m4

AUTOMAKE_OPIONS=foreign no-dependencies subdir-objects

                bin_PROGRAMS = meer
                               meer_CPPFLAGS = -I$(top_srcdir) $(LIBFASTJSON_CFLAGS) $(LIBESTR_CFLAGS)
                                       meer_LDADD = $(LIBFASTJSON_LIBS) $(LIBLOGNORM_LIBS) $(LIBESTR_LIBS)

                                               meer_SOURCES = meer.c \
							      config-yaml.c \
							      util.c \
							      util-strlcpy.c \
							      util-strlcat.c \
							      util-signal.c \
							      util-base64.c \
							      lockfile.c \
							      waldo.c \
							      output.c \
							      classifications.c \
							      references.c \
							      sid-msg.c \
							      decode-json.c \
							      decode-json-alert.c \
							      output-plugins/mysql.c


                                                       install-data-local:

