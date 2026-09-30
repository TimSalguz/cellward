/*
 * The one piece of C in cellward (`cellward-oc-auth`, docs/PERMISSIONS.md
 * §11.17): libopenconnect reports its progress through a printf-style
 * callback, and stable Rust cannot define a variadic function. This formats
 * the line — bounded, into a buffer of its own — and hands it to Rust, which
 * does the rest.
 */
#include <stdarg.h>
#include <stdio.h>

void cellward_oc_progress(void *privdata, int level, const char *text);

void cellward_oc_progress_shim(void *privdata, int level, const char *fmt, ...)
{
	char line[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	cellward_oc_progress(privdata, level, line);
}
