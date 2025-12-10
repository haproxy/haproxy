#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/mux_h2-t.h>
#include <haproxy/proxy-t.h>
#include <haproxy/tools.h>

/*******************************************************/
/* functions below are dedicated to the config parsers */
/*******************************************************/

/* config parser for global "tune.h2.{fe,be}.glitches-threshold" */
static int h2_parse_glitches_threshold(char **args, int section_type, struct proxy *curpx,
				       const struct proxy *defpx, const char *file, int line,
				       char **err)
{
	int *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend */
	vptr = (args[0][8] == 'b') ? &h2_be_glitches_threshold : &h2_fe_glitches_threshold;

	*vptr = atoi(args[1]);
	if (*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.header-table-size" */
static int h2_parse_header_table_size(char **args, int section_type, struct proxy *curpx,
                                      const struct proxy *defpx, const char *file, int line,
                                      char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_header_table_size = atoi(args[1]);
	if (h2_settings_header_table_size < 4096 || h2_settings_header_table_size > 65536) {
		memprintf(err, "'%s' expects a numeric value between 4096 and 65536.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.,}initial-window-size" */
static int h2_parse_initial_window_size(char **args, int section_type, struct proxy *curpx,
                                        const struct proxy *defpx, const char *file, int line,
                                        char **err)
{
	int *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend/default */
	vptr = (args[0][8] == 'b') ? &h2_be_settings_initial_window_size :
	       (args[0][8] == 'f') ? &h2_fe_settings_initial_window_size :
	       &h2_settings_initial_window_size;

	*vptr = atoi(args[1]);
	if (*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.,}max-concurrent-streams" */
static int h2_parse_max_concurrent_streams(char **args, int section_type, struct proxy *curpx,
                                           const struct proxy *defpx, const char *file, int line,
                                           char **err)
{
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend/default */
	vptr = (args[0][8] == 'b') ? &h2_be_settings_max_concurrent_streams :
	       (args[0][8] == 'f') ? &h2_fe_settings_max_concurrent_streams :
	       &h2_settings_max_concurrent_streams;

	*vptr = atoi(args[1]);
	if ((int)*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.fe.max-total-streams" */
static int h2_parse_max_total_streams(char **args, int section_type, struct proxy *curpx,
				      const struct proxy *defpx, const char *file, int line,
				      char **err)
{
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* frontend only for now */
	vptr = &h2_fe_max_total_streams;

	*vptr = atoi(args[1]);
	if ((int)*vptr < 0) {
		memprintf(err, "'%s' expects a positive numeric value.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.max-frame-size" */
static int h2_parse_max_frame_size(char **args, int section_type, struct proxy *curpx,
                                   const struct proxy *defpx, const char *file, int line,
                                   char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	h2_settings_max_frame_size = atoi(args[1]);
	if (h2_settings_max_frame_size < 16384 || h2_settings_max_frame_size > 16777215) {
		memprintf(err, "'%s' expects a numeric value between 16384 and 16777215.", args[0]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.{be.,fe.}rxbuf" */
static int h2_parse_rxbuf(char **args, int section_type, struct proxy *curpx,
                          const struct proxy *defpx, const char *file, int line,
                          char **err)
{
	const char *errptr;
	uint *vptr;

	if (too_many_args(1, args, err, NULL))
		return -1;

	/* backend/frontend */
	vptr = (args[0][8] == 'b') ? &h2_be_rxbuf : &h2_fe_rxbuf;

	*vptr = atoi(args[1]);
	if ((errptr = parse_size_err(args[1], vptr)) != NULL) {
		memprintf(err, "'%s': unexpected character '%c' in size argument '%s'.", args[0], *errptr, args[1]);
		return -1;
	}
	return 0;
}

/* config parser for global "tune.h2.zero-copy-fwd-send" */
static int h2_parse_zero_copy_fwd_snd(char **args, int section_type, struct proxy *curpx,
					  const struct proxy *defpx, const char *file, int line,
					  char **err)
{
	if (too_many_args(1, args, err, NULL))
		return -1;

	if (strcmp(args[1], "on") == 0)
		global.tune.no_zero_copy_fwd &= ~NO_ZERO_COPY_FWD_H2_SND;
	else if (strcmp(args[1], "off") == 0)
		global.tune.no_zero_copy_fwd |= NO_ZERO_COPY_FWD_H2_SND;
	else {
		memprintf(err, "'%s' expects 'on' or 'off'.", args[0]);
		return -1;
	}
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.h2.be.glitches-threshold",  h2_parse_glitches_threshold     },
	{ CFG_GLOBAL, "tune.h2.be.initial-window-size", h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.be.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.be.rxbuf",               h2_parse_rxbuf                  },
	{ CFG_GLOBAL, "tune.h2.fe.glitches-threshold",  h2_parse_glitches_threshold     },
	{ CFG_GLOBAL, "tune.h2.fe.initial-window-size", h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.fe.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.fe.max-total-streams",   h2_parse_max_total_streams      },
	{ CFG_GLOBAL, "tune.h2.fe.rxbuf",               h2_parse_rxbuf                  },
	{ CFG_GLOBAL, "tune.h2.header-table-size",      h2_parse_header_table_size      },
	{ CFG_GLOBAL, "tune.h2.initial-window-size",    h2_parse_initial_window_size    },
	{ CFG_GLOBAL, "tune.h2.max-concurrent-streams", h2_parse_max_concurrent_streams },
	{ CFG_GLOBAL, "tune.h2.max-frame-size",         h2_parse_max_frame_size         },
	{ CFG_GLOBAL, "tune.h2.zero-copy-fwd-send",     h2_parse_zero_copy_fwd_snd },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
