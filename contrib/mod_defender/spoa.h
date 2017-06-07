/*
 * Mod Defender for HAProxy
 *
 * Copyright 2017 HAProxy Technologies, Dragan Dosen <ddosen@haproxy.com>
 *
 * Based on "A Random IP reputation service acting as a Stream Processing Offload Agent"
 * Copyright 2016 HAProxy Technologies, Christopher Faulet <cfaulet@haproxy.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 3 of the License, or (at your option) any later version.
 *
 */
#ifndef __SPOA_H__
#define __SPOA_H__

#include <sys/time.h>
#undef LIST_HEAD

#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/thread.h>

#define LOG(worker, fmt, args...)                                       \
	do {								\
		struct timeval  now;					\
                                                                        \
		gettimeofday(&now, NULL);				\
		fprintf(stderr, "%ld.%06ld [%02d] " fmt "\n",		\
			now.tv_sec, now.tv_usec, (worker)->id, ##args);	\
	} while (0)

struct worker {
	pthread_t           thread;
	int                 id;
	struct event_base  *base;
	struct event       *monitor_event;

	struct list         engines;

	unsigned int        nbclients;
	struct list         clients;

	struct list         frames;
};

extern struct worker null_worker;

#endif /* __SPOA_H__ */
