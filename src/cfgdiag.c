#include <stdarg.h>
#include <stdlib.h>

#include <haproxy/cfgdiag.h>
#include <haproxy/log.h>

/* Use this fonction to emit diagnostic.
 * This can be used as a shortcut to set value pointed by <ret> to 1 at the
 * same time.
 */
static inline void diag_warning(int *ret, char *fmt, ...)
{
	va_list argp;

	va_start(argp, fmt);
	*ret = 1;
	_ha_vdiag_warning(fmt, argp);
	va_end(argp);
}

/* Use this for dynamic allocation in diagnostics.
 * In case of allocation failure, this will immediately terminates haproxy.
 */
static inline void *diag_alloc(size_t size)
{
	void *out = NULL;

	if (!(out = malloc(size))) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	return out;
}

/* Placeholder to execute various diagnostic checks after the configuration file
 * has been fully parsed. It will output a warning for each diagnostic found.
 *
 * Returns 0 if no diagnostic message has been found else 1.
 */
int cfg_run_diagnostics()
{
	int ret = 0;
	return ret;
}
