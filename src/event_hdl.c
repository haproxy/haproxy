/*
 * general purpose event handlers management
 *
 * Copyright 2022 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2.1 of the License, or (at your option) any later version.
 *
 */

#include <string.h>
#include <haproxy/event_hdl.h>
#include <haproxy/compiler.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>
#include <haproxy/errors.h>
#include <haproxy/xxhash.h>

/* event types changes in event_hdl-t.h file should be reflected in the
 * map below to allow string to type and type to string conversions
 */
static struct event_hdl_sub_type_map event_hdl_sub_type_map[] = {
	{"NONE",                EVENT_HDL_SUB_NONE},
	{"SERVER",              EVENT_HDL_SUB_SERVER},
	{"SERVER_ADD",          EVENT_HDL_SUB_SERVER_ADD},
	{"SERVER_DEL",          EVENT_HDL_SUB_SERVER_DEL},
};

/* internal types (only used in this file) */
struct event_hdl_async_task_default_ctx
{
	event_hdl_async_equeue e_queue; /* event queue list */
	event_hdl_cb_async func; /* event handling func */
};

/* memory pools declarations */
DECLARE_STATIC_POOL(pool_head_sub, "ehdl_sub", sizeof(struct event_hdl_sub));
DECLARE_STATIC_POOL(pool_head_sub_event, "ehdl_sub_e", sizeof(struct event_hdl_async_event));
DECLARE_STATIC_POOL(pool_head_sub_event_data, "ehdl_sub_ed", sizeof(struct event_hdl_async_event_data));
DECLARE_STATIC_POOL(pool_head_sub_taskctx, "ehdl_sub_tctx", sizeof(struct event_hdl_async_task_default_ctx));

/* global subscription list (implicit where NULL is used as sublist argument) */
static struct mt_list global_event_hdl_sub_list = MT_LIST_HEAD_INIT(global_event_hdl_sub_list);

/* TODO: will become a config tunable
 * ie: tune.events.max-async-notif-at-once
 */
static int event_hdl_async_max_notif_at_once = 10;

/* general purpose hashing function when you want to compute
 * an ID based on <scope> x <name>
 * It is your responsibility to make sure <scope> is not used
 * elsewhere in the code (or that you are fine with sharing
 * the scope).
 */
inline uint64_t event_hdl_id(const char *scope, const char *name)
{
	XXH64_state_t state;

	XXH64_reset(&state, 0);
	XXH64_update(&state, scope, strlen(scope));
	XXH64_update(&state, name, strlen(name));
	return XXH64_digest(&state);
}

/* takes a sub_type as input, returns corresponding sub_type
 * printable string or "N/A" if not found.
 * If not found, an error will be reported to stderr so the developers
 * know that a sub_type is missing its associated string in event_hdl-t.h
 */
const char *event_hdl_sub_type_to_string(struct event_hdl_sub_type sub_type)
{
	int it;

	for (it = 0; it < (int)(sizeof(event_hdl_sub_type_map) / sizeof(event_hdl_sub_type_map[0])); it++) {
		if (sub_type.family == event_hdl_sub_type_map[it].type.family &&
		    sub_type.subtype == event_hdl_sub_type_map[it].type.subtype)
			return event_hdl_sub_type_map[it].name;
	}
	ha_alert("event_hdl-t.h: missing sub_type string representation.\n"
		 "Please reflect any changes in event_hdl_sub_type_map.\n");
	return "N/A";
}

/* returns the internal sub_type corresponding
 * to the printable representation <name>
 * or EVENT_HDL_SUB_NONE if no such event exists
 * (see event_hdl-t.h for the complete list of supported types)
 */
struct event_hdl_sub_type event_hdl_string_to_sub_type(const char *name)
{
	int it;

	for (it = 0; it < (int)(sizeof(event_hdl_sub_type_map) / sizeof(event_hdl_sub_type_map[0])); it++) {
		if (!strcmp(name, event_hdl_sub_type_map[it].name))
			return event_hdl_sub_type_map[it].type;
	}
	return EVENT_HDL_SUB_NONE;
}

/* Takes <subscriptions> sub list as input, returns a printable string
 * containing every sub_types contained in <subscriptions>
 * separated by '|' char.
 * Returns NULL if no sub_types are found in <subscriptions>
 * This functions leverages memprintf, thus it is up to the
 * caller to free the returned value (if != NULL) when he no longer
 * uses it.
 */
char *event_hdl_sub_type_print(struct event_hdl_sub_type subscriptions)
{
	char *out = NULL;
	int it;
	uint8_t first = 1;

	for (it = 0; it < (int)(sizeof(event_hdl_sub_type_map) / sizeof(event_hdl_sub_type_map[0])); it++) {
		if (subscriptions.family == event_hdl_sub_type_map[it].type.family &&
		    ((subscriptions.subtype & event_hdl_sub_type_map[it].type.subtype) ==
		     event_hdl_sub_type_map[it].type.subtype)) {
			if (first) {
				memprintf(&out, "%s", event_hdl_sub_type_map[it].name);
				first--;
			}
			else
				memprintf(&out, "%s%s%s", out, "|", event_hdl_sub_type_map[it].name);
		}
	}

	return out;
}

/* event_hdl debug/reporting function */
typedef void (*event_hdl_report_hdl_state_func)(const char *fmt, ...);
static void event_hdl_report_hdl_state(event_hdl_report_hdl_state_func report_func,
                                       const struct event_hdl *hdl, const char *what, const char *state)
{
	report_func("[event_hdl]:%s (%s)'#%llu@%s': %s\n",
		    what,
		    (hdl->async) ? "ASYNC" : "SYNC",
		    (long long unsigned int)hdl->id,
		    hdl->dorigin,
		    state);
}

void event_hdl_async_free_event(struct event_hdl_async_event *e)
{
	if (unlikely(event_hdl_sub_type_equal(e->type, EVENT_HDL_SUB_END))) {
		/* last event for hdl, special case */
		/* free subscription entry as we're the last one still using it
		 * (it is already removed from mt_list, no race can occur)
		 */
		event_hdl_drop(e->sub_mgmt.this);
	}
	else if (e->_data &&
	         HA_ATOMIC_SUB_FETCH(&e->_data->refcount, 1) == 0) {
		/* we are the last event holding reference to event data - free required */
		pool_free(pool_head_sub_event_data, e->_data); /* data wrapper */
	}
	pool_free(pool_head_sub_event, e);
}

/* task handler used for normal async subscription mode
 * if you use advanced async subscription mode, you can use this
 * as an example to implement your own task wrapper
 */
static struct task *event_hdl_async_task_default(struct task *task, void *ctx, unsigned int state)
{
	struct tasklet *tl = (struct tasklet *)task;
	struct event_hdl_async_task_default_ctx	*task_ctx = ctx;
	struct event_hdl_async_event *event;
	int max_notif_at_once_it = 0;
	uint8_t done = 0;

	/* run through e_queue, and call func() for each event
	 * if we read END event, it indicates we must stop:
	 * no more events to come (handler is unregistered)
	 * so we must free task_ctx and stop task
	 */
	while (max_notif_at_once_it < event_hdl_async_max_notif_at_once &&
	       (event = event_hdl_async_equeue_pop(&task_ctx->e_queue)))
	{
		if (event_hdl_sub_type_equal(event->type, EVENT_HDL_SUB_END)) {
			done = 1;
			event_hdl_async_free_event(event);
			/* break is normally not even required, EVENT_HDL_SUB_END
			 * is guaranteed to be last event of e_queue
			 * (because in normal mode one sub == one e_queue)
			 */
			break;
		}
		else {
			struct event_hdl_cb cb;

			cb.e_type = event->type;
			cb.e_data = event->data;
			cb.sub_mgmt = &event->sub_mgmt;
			cb._sync = 0;

			/* call user function */
			task_ctx->func(&cb, event->private);
			max_notif_at_once_it++;
		}
		event_hdl_async_free_event(event);
	}

	if (done) {
		/* our job is done, subscription is over: no more events to come */
		pool_free(pool_head_sub_taskctx, task_ctx);
		tasklet_free(tl);
		return NULL;
	}
	return task;
}

/* internal subscription mgmt functions */
static inline struct event_hdl_sub_type _event_hdl_getsub(struct event_hdl_sub *cur_sub)
{
	return cur_sub->sub;
}

static inline struct event_hdl_sub_type _event_hdl_getsub_async(struct event_hdl_sub *cur_sub)
{
	struct mt_list lock;
	struct event_hdl_sub_type type = EVENT_HDL_SUB_NONE;

	lock = MT_LIST_LOCK_ELT(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		type = _event_hdl_getsub(cur_sub);
	// else already removed
	MT_LIST_UNLOCK_ELT(&cur_sub->mt_list, lock);
	return type;
}

static inline int _event_hdl_resub(struct event_hdl_sub *cur_sub, struct event_hdl_sub_type type)
{
	if (!event_hdl_sub_family_equal(cur_sub->sub, type))
		return 0; /* family types differ, do nothing */
	cur_sub->sub.subtype = type.subtype; /* new subtype assignment */
	return 1;
}

static inline int _event_hdl_resub_async(struct event_hdl_sub *cur_sub, struct event_hdl_sub_type type)
{
	int status = 0;
	struct mt_list lock;

	lock = MT_LIST_LOCK_ELT(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		status = _event_hdl_resub(cur_sub, type);
	// else already removed
	MT_LIST_UNLOCK_ELT(&cur_sub->mt_list, lock);
	return status;
}

static inline void _event_hdl_unsubscribe(struct event_hdl_sub *del_sub)
{
	struct mt_list lock;

	if (del_sub->hdl.async) {
		/* ASYNC SUB MODE */
		/* push EVENT_HDL_SUB_END (to notify the task that the subscription is dead) */

		/* push END EVENT in busy state so we can safely wakeup
		 * the task before releasing it.
		 * Not doing that would expose us to a race where the task could've already
		 * consumed the END event before the wakeup, and some tasks
		 * kill themselves (ie: normal async mode) when they receive such event
		 */
		lock = MT_LIST_APPEND_LOCKED(del_sub->hdl.async_equeue, &del_sub->async_end->mt_list);

		/* wake up the task */
		tasklet_wakeup(del_sub->hdl.async_task);

		/* unlock END EVENT (we're done, the task is now free to consume it) */
		MT_LIST_UNLOCK_ELT(&del_sub->async_end->mt_list, lock);

		/* we don't free sub here
		* freeing will be performed by async task so it can safely rely
		* on the pointer until it notices it
		*/
	} else {
		/* SYNC SUB MODE */

		/* we can directly free the subscription:
		 * no other thread can access it since we successfully
		 * removed it from the list
		 */
		event_hdl_drop(del_sub);
	}
}

static inline void _event_hdl_unsubscribe_async(struct event_hdl_sub *del_sub)
{
	if (!MT_LIST_DELETE(&del_sub->mt_list))
		return; /* already removed (but may be pending in e_queues) */
	_event_hdl_unsubscribe(del_sub);
}

/* sub_mgmt function pointers (for handlers) */
static struct event_hdl_sub_type event_hdl_getsub_sync(const struct event_hdl_sub_mgmt *mgmt)
{
	if (!mgmt)
		return EVENT_HDL_SUB_NONE;

	if (!mgmt->this)
		return EVENT_HDL_SUB_NONE; /* already removed from sync ctx */
	return _event_hdl_getsub(mgmt->this);
}

static struct event_hdl_sub_type event_hdl_getsub_async(const struct event_hdl_sub_mgmt *mgmt)
{
	if (!mgmt)
		return EVENT_HDL_SUB_NONE;

	return _event_hdl_getsub_async(mgmt->this);
}

static int event_hdl_resub_sync(const struct event_hdl_sub_mgmt *mgmt, struct event_hdl_sub_type type)
{
	if (!mgmt)
		return 0;

	if (!mgmt->this)
		return 0; /* already removed from sync ctx */
	return _event_hdl_resub(mgmt->this, type);
}

static int event_hdl_resub_async(const struct event_hdl_sub_mgmt *mgmt, struct event_hdl_sub_type type)
{
	if (!mgmt)
		return 0;

	return _event_hdl_resub_async(mgmt->this, type);
}

static void event_hdl_unsubscribe_sync(const struct event_hdl_sub_mgmt *mgmt)
{
	if (!mgmt)
		return;

	if (!mgmt->this)
		return; /* already removed from sync ctx */

	/* assuming that publish sync code will notice that mgmt->this is NULL
	 * and will perform the list removal using MT_LIST_DELETE_SAFE and
	 * _event_hdl_unsubscribe()
	 * while still owning the lock
	 */
	((struct event_hdl_sub_mgmt *)mgmt)->this = NULL;
}

static void event_hdl_unsubscribe_async(const struct event_hdl_sub_mgmt *mgmt)
{
	if (!mgmt)
		return;

	_event_hdl_unsubscribe_async(mgmt->this);
}

#define EVENT_HDL_SUB_MGMT_ASYNC(_sub)  (struct event_hdl_sub_mgmt){ .this = _sub,				\
                                                                     .getsub = event_hdl_getsub_async,		\
                                                                     .resub = event_hdl_resub_async,		\
                                                                     .unsub = event_hdl_unsubscribe_async}
#define EVENT_HDL_SUB_MGMT_SYNC(_sub)   (struct event_hdl_sub_mgmt){ .this = _sub,				\
                                                                     .getsub = event_hdl_getsub_sync,		\
                                                                     .resub = event_hdl_resub_sync,		\
                                                                     .unsub = event_hdl_unsubscribe_sync}

struct event_hdl_sub *event_hdl_subscribe_ptr(event_hdl_sub_list *sub_list,
                                              struct event_hdl_sub_type e_type, struct event_hdl hdl)
{
	struct event_hdl_sub *new_sub;
	struct mt_list *elt1, elt2;
	uint8_t found = 0;
	struct event_hdl_async_task_default_ctx	*task_ctx;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	/* hdl API consistency check */
	/*FIXME: do we need to ensure that if private is set, private_free should be set as well? */
	BUG_ON((!hdl.async && !hdl.sync_ptr) ||
	       (hdl.async == EVENT_HDL_ASYNC_MODE_NORMAL && !hdl.async_ptr) ||
	       (hdl.async == EVENT_HDL_ASYNC_MODE_ADVANCED &&
		(!hdl.async_equeue || !hdl.async_task)));

	/* first check if such identified hdl is not already registered */
	if (hdl.id) {
		mt_list_for_each_entry_safe(new_sub, sub_list, mt_list, elt1, elt2) {
			if (hdl.id == new_sub->hdl.id) {
				/* we found matching registered hdl */
				found = 1;
				break;
			}
		}
	}

	if (found) {
		/* error already registered */
		event_hdl_report_hdl_state(ha_warning, &hdl, "SUB", "could not subscribe: subscription with this id already exists");
		return NULL;
	}

	new_sub = pool_alloc(pool_head_sub);
	if (new_sub == NULL) {
		goto new_sub_memory_error;
	}

	/* assignments */
	new_sub->sub.family = e_type.family;
	new_sub->sub.subtype = e_type.subtype;
	new_sub->hdl = hdl;

	if (hdl.async) {
		/* async END event pre-allocation */
		new_sub->async_end = pool_alloc(pool_head_sub_event);
		if (!new_sub->async_end) {
			/* memory error */
			goto new_sub_memory_error_event_end;
		}
		if (hdl.async == EVENT_HDL_ASYNC_MODE_NORMAL) {
			/* normal mode: no task provided, we must initialize it */

			/* initialize task context */
			task_ctx = pool_alloc(pool_head_sub_taskctx);

			if (!task_ctx) {
				/* memory error */
				goto new_sub_memory_error_task_ctx;
			}
			MT_LIST_INIT(&task_ctx->e_queue);
			task_ctx->func = new_sub->hdl.async_ptr;

			new_sub->hdl.async_equeue = &task_ctx->e_queue;
			new_sub->hdl.async_task = tasklet_new();

			if (!new_sub->hdl.async_task) {
				/* memory error */
				goto new_sub_memory_error_task;
			}
			new_sub->hdl.async_task->context = task_ctx;
			new_sub->hdl.async_task->process = event_hdl_async_task_default;
		}
		/* registration cannot fail anymore */

		/* initialize END event (used to notify about subscription ending)
		 * used by both normal and advanced mode:
		 * 	- to safely terminate the task in normal mode
		 * 	- to safely free subscription and
		 * 	  keep track of active subscriptions in advanced mode
		 */
		new_sub->async_end->type = EVENT_HDL_SUB_END;
		new_sub->async_end->sub_mgmt = EVENT_HDL_SUB_MGMT_ASYNC(new_sub);
		new_sub->async_end->private = new_sub->hdl.private;
		new_sub->async_end->_data = NULL;
		MT_LIST_INIT(&new_sub->async_end->mt_list);
	}
	/* set refcount to 2:
	 * 1 for handler (because handler can manage the subscription itself)
	 * 1 for caller (will be dropped automatically if caller use the non-ptr version)
	 */
	new_sub->refcount = 2;

	/* Append in list (global or user specified list).
	 * For now, append when sync mode, and insert when async mode
	 * so that async handlers are executed first
	 */
	MT_LIST_INIT(&new_sub->mt_list);
	if (hdl.async) {
		/* async mode, insert at the beginning of the list */
		MT_LIST_INSERT(sub_list, &new_sub->mt_list);
	} else {
		/* sync mode, append at the end of the list */
		MT_LIST_APPEND(sub_list, &new_sub->mt_list);
	}

	return new_sub;

new_sub_memory_error_task:
	pool_free(pool_head_sub_taskctx, task_ctx);
new_sub_memory_error_task_ctx:
	pool_free(pool_head_sub_event, new_sub->async_end);
new_sub_memory_error_event_end:
	pool_free(pool_head_sub, new_sub);
new_sub_memory_error:

	event_hdl_report_hdl_state(ha_warning, &hdl, "SUB", "could not register subscription due to memory error");

	return NULL;
}

void event_hdl_take(struct event_hdl_sub *sub)
{
	HA_ATOMIC_INC(&sub->refcount);
}

void event_hdl_drop(struct event_hdl_sub *sub)
{
	if (HA_ATOMIC_SUB_FETCH(&sub->refcount, 1) != 0)
		return;

	/* we are the last event holding reference to event data - free required */
	if (sub->hdl.private_free) {
		/* free private data if specified upon registration */
		sub->hdl.private_free(sub->hdl.private);
	}
	pool_free(pool_head_sub, sub);
}

int event_hdl_resubscribe(struct event_hdl_sub *cur_sub, struct event_hdl_sub_type type)
{
	return _event_hdl_resub_async(cur_sub, type);
}

void event_hdl_unsubscribe(struct event_hdl_sub *del_sub)
{
	_event_hdl_unsubscribe_async(del_sub);
	/* drop refcount, assuming caller no longer use ptr */
	event_hdl_drop(del_sub);
}

int event_hdl_subscribe(event_hdl_sub_list *sub_list, struct event_hdl_sub_type e_type, struct event_hdl hdl)
{
	struct event_hdl_sub *sub;

	sub = event_hdl_subscribe_ptr(sub_list, e_type, hdl);
	if (sub) {
		/* drop refcount because the user is not willing to hold a reference */
		event_hdl_drop(sub);
		return 1;
	}
	return 0;
}

/* Subscription external lookup functions
 */
int event_hdl_lookup_unsubscribe(event_hdl_sub_list *sub_list,
                                 uint64_t lookup_id)
{
	struct event_hdl_sub *del_sub = NULL;
	struct mt_list *elt1, elt2;
	int found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	mt_list_for_each_entry_safe(del_sub, sub_list, mt_list, elt1, elt2) {
		if (lookup_id == del_sub->hdl.id) {
			/* we found matching registered hdl */
			MT_LIST_DELETE_SAFE(elt1);
			_event_hdl_unsubscribe(del_sub);
			found = 1;
			break; /* id is unique, stop searching */
		}
	}
	return found;
}

int event_hdl_lookup_resubscribe(event_hdl_sub_list *sub_list,
                                 uint64_t lookup_id, struct event_hdl_sub_type type)
{
	struct event_hdl_sub *cur_sub = NULL;
	struct mt_list *elt1, elt2;
	int status = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	mt_list_for_each_entry_safe(cur_sub, sub_list, mt_list, elt1, elt2) {
		if (lookup_id == cur_sub->hdl.id) {
			/* we found matching registered hdl */
			status = _event_hdl_resub(cur_sub, type);
			break; /* id is unique, stop searching */
		}
	}
	return status;
}

struct event_hdl_sub *event_hdl_lookup_take(event_hdl_sub_list *sub_list,
                                            uint64_t lookup_id)
{
	struct event_hdl_sub *cur_sub = NULL;
	struct mt_list *elt1, elt2;
	uint8_t found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	mt_list_for_each_entry_safe(cur_sub, sub_list, mt_list, elt1, elt2) {
		if (lookup_id == cur_sub->hdl.id) {
			/* we found matching registered hdl */
			event_hdl_take(cur_sub);
			found = 1;
			break; /* id is unique, stop searching */
		}
	}
	if (found)
		return cur_sub;
	return NULL;
}

/* event publishing functions
 */
static int _event_hdl_publish(event_hdl_sub_list *sub_list, struct event_hdl_sub_type e_type,
                              const struct event_hdl_cb_data *data)
{
	struct event_hdl_sub *cur_sub;
	struct mt_list *elt1, elt2;
	struct event_hdl_async_event_data *async_data = NULL; /* reuse async data for multiple async hdls */
	int error = 0;

	mt_list_for_each_entry_safe(cur_sub, sub_list, mt_list, elt1, elt2) {
		/* notify each function that has subscribed to sub_family.type */
		if ((cur_sub->sub.family == e_type.family) &&
		    ((cur_sub->sub.subtype & e_type.subtype) == e_type.subtype)) {
			/* hdl should be notified */
			if (!cur_sub->hdl.async) {
				/* sync mode: simply call cb pointer
				* it is up to the callee to schedule a task if needed or
				* take specific precautions in order to return as fast as possible
				* and not use locks that are already held by the caller
				*/
				struct event_hdl_cb cb;
				struct event_hdl_sub_mgmt sub_mgmt;

				sub_mgmt = EVENT_HDL_SUB_MGMT_SYNC(cur_sub);
				cb.e_type = e_type;
				if (data)
					cb.e_data = data->_ptr;
				else
					cb.e_data = NULL;
				cb.sub_mgmt = &sub_mgmt;
				cb._sync = 1;

				/* call user function */
				cur_sub->hdl.sync_ptr(&cb, cur_sub->hdl.private);

				if (!sub_mgmt.this) {
					/* user has performed hdl unsub
					 * we must remove it from the list
					 */
					MT_LIST_DELETE_SAFE(elt1);
					/* then free it */
					_event_hdl_unsubscribe(cur_sub);
				}
			} else {
				/* async mode: here we need to prepare event data
				 * and push it to the event_queue of the task(s)
				 * responsible for consuming the events of current
				 * subscription.
				 * Once the event is pushed, we wake up the associated task.
				 * This feature depends on <haproxy/task> that also
				 * depends on <haproxy/pool>:
				 * If STG_PREPARE+STG_POOL is not performed prior to publishing to
				 * async handler, program may crash.
				 * Hopefully, STG_PREPARE+STG_POOL should be done early in
				 * HAProxy startup sequence.
				 */
				struct event_hdl_async_event *new_event;

				new_event = pool_alloc(pool_head_sub_event);
				if (!new_event) {
					error = 1;
					break; /* stop on error */
				}
				new_event->type = e_type;
				new_event->private = cur_sub->hdl.private;
				new_event->sub_mgmt = EVENT_HDL_SUB_MGMT_ASYNC(cur_sub);
				if (data) {
					/* if this fails, please adjust EVENT_HDL_ASYNC_EVENT_DATA in
					 * event_hdl-t.h file
					 */
					BUG_ON(data->_size > sizeof(async_data->data));
					if (!async_data) {
						/* first async hdl reached - preparing async_data cache */
						async_data = pool_alloc(pool_head_sub_event_data);
						if (!async_data) {
							error = 1;
							pool_free(pool_head_sub_event, new_event);
							break; /* stop on error */
						}

						/* async data assignment */
						memcpy(async_data->data, data->_ptr, data->_size);
						async_data->refcount = 0; /* initialize async->refcount (first use, atomic operation not required) */
					}
					new_event->_data = async_data;
					new_event->data = async_data->data;
					/* increment refcount because multiple hdls could
					 * use the same async_data
					 */
					HA_ATOMIC_INC(&async_data->refcount);
				} else
					new_event->data = NULL;

				/* appending new event to event hdl queue */
				MT_LIST_INIT(&new_event->mt_list);
				MT_LIST_APPEND(cur_sub->hdl.async_equeue, &new_event->mt_list);

				/* wake up the task */
				tasklet_wakeup(cur_sub->hdl.async_task);
			} /* end async mode */
		} /* end hdl should be notified */
	} /* end mt_list */
	if (error) {
		event_hdl_report_hdl_state(ha_warning, &cur_sub->hdl, "PUBLISH", "memory error");
		return 0;
	}
	return 1;
}

/* Publish function should not be used from high calling rate or time sensitive
 * places for now, because list lookup based on e_type is not optimized at
 * all!
 * Returns 1 in case of SUCCESS:
 *	Subscribed handlers were notified successfully
 * Returns 0 in case of FAILURE:
 *	FAILURE means memory error while handling the very first async handler from
 *	the subscription list.
 *	As async handlers are executed first within the list, when such failure occurs
 *	you can safely assume that no events were published for the current call
 */
int event_hdl_publish(event_hdl_sub_list *sub_list,
                      struct event_hdl_sub_type e_type, const struct event_hdl_cb_data *data)
{
	if (!e_type.family) {
		/* do nothing, these types are reserved for internal use only
		 * (ie: unregistering) */
		return 0;
	}
	if (sub_list) {
		/* if sublist is provided, first publish event to list subscribers */
		return _event_hdl_publish(sub_list, e_type, data);
	} else {
		/* publish to global list */
		return _event_hdl_publish(&global_event_hdl_sub_list, e_type, data);
	}
}

/* when a subscription list is no longer used, call this
 * to do the cleanup and make sure all related subscriptions are
 * safely ended according to their types
 */
void event_hdl_sub_list_destroy(event_hdl_sub_list *sub_list)
{
	struct event_hdl_sub *cur_sub;
	struct mt_list *elt1, elt2;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */
	mt_list_for_each_entry_safe(cur_sub, sub_list, mt_list, elt1, elt2) {
		/* remove cur elem from list */
		MT_LIST_DELETE_SAFE(elt1);
		/* then free it */
		_event_hdl_unsubscribe(cur_sub);
	}
}
