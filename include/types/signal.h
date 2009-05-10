/*
 * Asynchronous signal delivery functions descriptors.
 *
 * Copyright 2000-2009 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <signal.h>
#include <common/config.h>
#include <common/standard.h>

struct signal_descriptor {
	int count;  /* number of times raised */
	void (*handler)(int sig);
};
