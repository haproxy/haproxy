/*
 * activity measurement functions.
 *
 * Copyright 2000-2018 Willy Tarreau <w@1wt.eu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <common/config.h>
#include <common/standard.h>
#include <common/hathreads.h>
#include <types/activity.h>
#include <proto/freq_ctr.h>

/* One struct per thread containing all collected measurements */
struct activity activity[MAX_THREADS] __attribute__((aligned(64))) = { };


/* Updates the current thread's statistics about stolen CPU time. The unit for
 * <stolen> is half-milliseconds.
 */
void report_stolen_time(uint64_t stolen)
{
	activity[tid].cpust_total += stolen;
	update_freq_ctr(&activity[tid].cpust_1s, stolen);
	update_freq_ctr_period(&activity[tid].cpust_15s, 15000, stolen);
}
