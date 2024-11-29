/*
 * general purpose event handlers management
 *
 * Copyright 2022 HAProxy Technologies
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <string.h>
#include <haproxy/event_hdl.h>
#include <haproxy/compiler.h>
#include <haproxy/task.h>
#include <haproxy/tools.h>
#include <haproxy/errors.h>
#include <haproxy/signal.h>
#include <haproxy/xxhash.h>
#include <haproxy/cfgparse.h>

/* event types changes in event_hdl-t.h file should be reflected in the
 * map below to allow string to type and type to string conversions
 */
static struct event_hdl_sub_type_map event_hdl_sub_type_map[] = {
	{"NONE",                EVENT_HDL_SUB_NONE},
	{"SERVER",              EVENT_HDL_SUB_SERVER},
	{"SERVER_ADD",          EVENT_HDL_SUB_SERVER_ADD},
	{"SERVER_DEL",          EVENT_HDL_SUB_SERVER_DEL},
	{"SERVER_UP",           EVENT_HDL_SUB_SERVER_UP},
	{"SERVER_DOWN",         EVENT_HDL_SUB_SERVER_DOWN},
	{"SERVER_STATE",        EVENT_HDL_SUB_SERVER_STATE},
	{"SERVER_ADMIN",        EVENT_HDL_SUB_SERVER_ADMIN},
	{"SERVER_CHECK",        EVENT_HDL_SUB_SERVER_CHECK},
	{"SERVER_INETADDR",     EVENT_HDL_SUB_SERVER_INETADDR},
	{"PAT_REF",             EVENT_HDL_SUB_PAT_REF},
	{"PAT_REF_ADD",         EVENT_HDL_SUB_PAT_REF_ADD},
	{"PAT_REF_DEL",         EVENT_HDL_SUB_PAT_REF_DEL},
	{"PAT_REF_SET",         EVENT_HDL_SUB_PAT_REF_SET},
	{"PAT_REF_COMMIT",      EVENT_HDL_SUB_PAT_REF_COMMIT},
	{"PAT_REF_CLEAR",       EVENT_HDL_SUB_PAT_REF_CLEAR},
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

/* global event_hdl tunables (public variable) */
struct event_hdl_tune event_hdl_tune;

/* global subscription list (implicit where NULL is used as sublist argument) */
static event_hdl_sub_list global_event_hdl_sub_list;

/* every known subscription lists are tracked in this list (including the global one) */
static struct mt_list known_event_hdl_sub_list = MT_LIST_HEAD_INIT(known_event_hdl_sub_list);

static void _event_hdl_sub_list_destroy(event_hdl_sub_list *sub_list);

static void event_hdl_deinit(struct sig_handler *sh)
{
	event_hdl_sub_list *cur_list;
	struct mt_list back;

	/* destroy all known subscription lists */
	MT_LIST_FOR_EACH_ENTRY_UNLOCKED(cur_list, &known_event_hdl_sub_list, known, back) {
		/* remove cur elem from list and free it */
		_event_hdl_sub_list_destroy(cur_list);
		cur_list = NULL;
	}
}

static void event_hdl_init(void)
{
	/* initialize global subscription list */
	event_hdl_sub_list_init(&global_event_hdl_sub_list);
	/* register the deinit function, will be called on soft-stop */
	signal_register_fct(0, event_hdl_deinit, 0);

	/* set some default values */
	event_hdl_tune.max_events_at_once = EVENT_HDL_MAX_AT_ONCE;
}

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
		if (strcmp(name, event_hdl_sub_type_map[it].name) == 0)
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

static inline void _event_hdl_async_data_drop(struct event_hdl_async_event_data *data)
{
	if (HA_ATOMIC_SUB_FETCH(&data->refcount, 1) == 0) {
		/* we were the last one holding a reference to event data - free required */
		if (data->mfree) {
			/* Some event data members are dynamically allocated and thus
			 * require specific cleanup using user-provided function.
			 * We directly pass a pointer to internal data storage but
			 * we only expect the cleanup function to typecast it in the
			 * relevant data type to give enough context to the function to
			 * perform the cleanup on data members, and not actually freeing
			 * data pointer since it is our internal buffer :)
			 */
			data->mfree(&data->data);
		}
		pool_free(pool_head_sub_event_data, data);
	}
}

void event_hdl_async_free_event(struct event_hdl_async_event *e)
{
	if (unlikely(event_hdl_sub_type_equal(e->type, EVENT_HDL_SUB_END))) {
		/* last event for hdl, special case */
		/* free subscription entry as we're the last one still using it
		 * (it is already removed from mt_list, no race can occur)
		 */
		event_hdl_drop(e->sub_mgmt.this);
		HA_ATOMIC_DEC(&jobs);
	}
	else if (e->_data)
		_event_hdl_async_data_drop(e->_data); /* data wrapper */
	pool_free(pool_head_sub_event, e);
}

/* wakeup the task depending on its type:
 * normal async mode internally uses tasklets but advanced async mode
 * allows both tasks and tasklets.
 * While tasks and tasklets may be easily casted, we need to use the proper
 * API to wake them up (the waiting queues are exclusive).
 */
static void event_hdl_task_wakeup(struct tasklet *task)
{
	if (TASK_IS_TASKLET(task))
		tasklet_wakeup(task);
	else
		task_wakeup((struct task *)task, TASK_WOKEN_OTHER); /* TODO: switch to TASK_WOKEN_EVENT? */
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
	while (max_notif_at_once_it < event_hdl_tune.max_events_at_once &&
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

	lock = mt_list_lock_full(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		type = _event_hdl_getsub(cur_sub);
	// else already removed
	mt_list_unlock_full(&cur_sub->mt_list, lock);
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

	lock = mt_list_lock_full(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		status = _event_hdl_resub(cur_sub, type);
	// else already removed
	mt_list_unlock_full(&cur_sub->mt_list, lock);
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
		HA_ATOMIC_INC(&del_sub->hdl.async_equeue->size);
		mt_list_lock_elem(&del_sub->async_end->mt_list);
		lock = mt_list_lock_prev(&del_sub->hdl.async_equeue->head);

		/* wake up the task */
		event_hdl_task_wakeup(del_sub->hdl.async_task);

		/* unlock END EVENT (we're done, the task is now free to consume it) */
		mt_list_unlock_full(&del_sub->async_end->mt_list, lock);

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
	 * and will perform the list removal and _event_hdl_unsubscribe()
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
	struct event_hdl_sub *new_sub = NULL;
	struct mt_list back;
	struct event_hdl_async_task_default_ctx	*task_ctx = NULL;
	struct mt_list lock;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	/* hdl API consistency check */
	/*FIXME: do we need to ensure that if private is set, private_free should be set as well? */
	BUG_ON((!hdl.async && !hdl.sync_ptr) ||
	       (hdl.async == EVENT_HDL_ASYNC_MODE_NORMAL && !hdl.async_ptr) ||
	       (hdl.async == EVENT_HDL_ASYNC_MODE_ADVANCED &&
		(!hdl.async_equeue || !hdl.async_task)));

	new_sub = pool_alloc(pool_head_sub);
	if (new_sub == NULL) {
		goto memory_error;
	}

	/* assignments */
	new_sub->sub.family = e_type.family;
	new_sub->sub.subtype = e_type.subtype;
	new_sub->flags = 0;
	new_sub->hdl = hdl;

	if (hdl.async) {
		/* async END event pre-allocation */
		new_sub->async_end = pool_alloc(pool_head_sub_event);
		if (!new_sub->async_end) {
			/* memory error */
			goto memory_error;
		}
		if (hdl.async == EVENT_HDL_ASYNC_MODE_NORMAL) {
			/* normal mode: no task provided, we must initialize it */

			/* initialize task context */
			task_ctx = pool_alloc(pool_head_sub_taskctx);

			if (!task_ctx) {
				/* memory error */
				goto memory_error;
			}
			event_hdl_async_equeue_init(&task_ctx->e_queue);
			task_ctx->func = new_sub->hdl.async_ptr;

			new_sub->hdl.async_equeue = &task_ctx->e_queue;
			new_sub->hdl.async_task = tasklet_new();

			if (!new_sub->hdl.async_task) {
				/* memory error */
				goto memory_error;
			}
			new_sub->hdl.async_task->context = task_ctx;
			new_sub->hdl.async_task->process = event_hdl_async_task_default;
		}
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

	/* ready for registration */
	MT_LIST_INIT(&new_sub->mt_list);

	lock = mt_list_lock_full(&sub_list->known);

	/* check if such identified hdl is not already registered */
	if (hdl.id) {
		struct event_hdl_sub *cur_sub;
		uint8_t found = 0;

		MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
			if (hdl.id == cur_sub->hdl.id) {
				/* we found matching registered hdl */
				found = 1;
				break;
			}
		}
		if (found) {
			/* error already registered */
			mt_list_unlock_full(&sub_list->known, lock);
			event_hdl_report_hdl_state(ha_alert, &hdl, "SUB", "could not subscribe: subscription with this id already exists");
			goto cleanup;
		}
	}

	if (lock.next == &sub_list->known) {
		/* this is an expected corner case on de-init path, a subscribe attempt
		 * was made but the subscription list is already destroyed, we pretend
		 * it is a memory/IO error since it should not be long before haproxy
		 * enters the deinit() function anyway
		 */
		mt_list_unlock_full(&sub_list->known, lock);
		goto cleanup;
	}

	/* Append in list (global or user specified list).
	 * For now, append when sync mode, and insert when async mode
	 * so that async handlers are executed first
	 */
	if (hdl.async) {
		/* Prevent the task from being aborted on soft-stop: let's wait
		 * until the END event is acknowledged by the task.
		 * (decrease is performed in event_hdl_async_free_event())
		 *
		 * If we don't do this, event_hdl API will leak and we won't give
		 * a chance to the event-handling task to perform cleanup
		 */
		HA_ATOMIC_INC(&jobs);
		/* async mode, insert at the beginning of the list */
		MT_LIST_INSERT(&sub_list->head, &new_sub->mt_list);
	} else {
		/* sync mode, append at the end of the list */
		MT_LIST_APPEND(&sub_list->head, &new_sub->mt_list);
	}

	mt_list_unlock_full(&sub_list->known, lock);

	return new_sub;

 cleanup:
	if (new_sub) {
		if (hdl.async == EVENT_HDL_ASYNC_MODE_NORMAL) {
			tasklet_free(new_sub->hdl.async_task);
			pool_free(pool_head_sub_taskctx, task_ctx);
		}
		if (hdl.async)
			pool_free(pool_head_sub_event, new_sub->async_end);
		pool_free(pool_head_sub, new_sub);
	}

	return NULL;

 memory_error:
	event_hdl_report_hdl_state(ha_warning, &hdl, "SUB", "could not register subscription due to memory error");
	goto cleanup;
}

void event_hdl_take(struct event_hdl_sub *sub)
{
	HA_ATOMIC_INC(&sub->refcount);
}

void event_hdl_drop(struct event_hdl_sub *sub)
{
	if (HA_ATOMIC_SUB_FETCH(&sub->refcount, 1) != 0)
		return;

	/* we were the last one holding a reference to event sub - free required */
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

void _event_hdl_pause(struct event_hdl_sub *cur_sub)
{
	cur_sub->flags |= EHDL_SUB_F_PAUSED;
}

void event_hdl_pause(struct event_hdl_sub *cur_sub)
{
	struct mt_list lock;

	lock = mt_list_lock_full(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		_event_hdl_pause(cur_sub);
	// else already removed
	mt_list_unlock_full(&cur_sub->mt_list, lock);
}

void _event_hdl_resume(struct event_hdl_sub *cur_sub)
{
	cur_sub->flags &= ~EHDL_SUB_F_PAUSED;
}

void event_hdl_resume(struct event_hdl_sub *cur_sub)
{
	struct mt_list lock;

	lock = mt_list_lock_full(&cur_sub->mt_list);
	if (lock.next != &cur_sub->mt_list)
		_event_hdl_resume(cur_sub);
	// else already removed
	mt_list_unlock_full(&cur_sub->mt_list, lock);
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
	struct mt_list back;
	int found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	MT_LIST_FOR_EACH_ENTRY_LOCKED(del_sub, &sub_list->head, mt_list, back) {
		if (lookup_id == del_sub->hdl.id) {
			/* we found matching registered hdl */
			mt_list_unlock_self(&del_sub->mt_list);
			_event_hdl_unsubscribe(del_sub);
			del_sub = NULL;
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
	struct mt_list back;
	int status = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
		if (lookup_id == cur_sub->hdl.id) {
			/* we found matching registered hdl */
			status = _event_hdl_resub(cur_sub, type);
			break; /* id is unique, stop searching */
		}
	}
	return status;
}

int event_hdl_lookup_pause(event_hdl_sub_list *sub_list,
                           uint64_t lookup_id)
{
	struct event_hdl_sub *cur_sub = NULL;
	struct mt_list back;
	int found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
		if (lookup_id == cur_sub->hdl.id) {
			/* we found matching registered hdl */
			_event_hdl_pause(cur_sub);
			found = 1;
			break; /* id is unique, stop searching */
		}
	}
	return found;
}

int event_hdl_lookup_resume(event_hdl_sub_list *sub_list,
                            uint64_t lookup_id)
{
	struct event_hdl_sub *cur_sub = NULL;
	struct mt_list back;
	int found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
		if (lookup_id == cur_sub->hdl.id) {
			/* we found matching registered hdl */
			_event_hdl_resume(cur_sub);
			found = 1;
			break; /* id is unique, stop searching */
		}
	}
	return found;
}

struct event_hdl_sub *event_hdl_lookup_take(event_hdl_sub_list *sub_list,
                                            uint64_t lookup_id)
{
	struct event_hdl_sub *cur_sub = NULL;
	struct mt_list back;
	uint8_t found = 0;

	if (!sub_list)
		sub_list = &global_event_hdl_sub_list; /* fall back to global list */

	MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
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
	struct mt_list back;
	struct event_hdl_async_event_data *async_data = NULL; /* reuse async data for multiple async hdls */
	int error = 0;

	MT_LIST_FOR_EACH_ENTRY_LOCKED(cur_sub, &sub_list->head, mt_list, back) {
		/* notify each function that has subscribed to sub_family.type, unless paused */
		if ((cur_sub->sub.family == e_type.family) &&
		    ((cur_sub->sub.subtype & e_type.subtype) == e_type.subtype) &&
		    !(cur_sub->flags & EHDL_SUB_F_PAUSED)) {
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
					 * then free it.
					 */
					mt_list_unlock_self(&cur_sub->mt_list);
					_event_hdl_unsubscribe(cur_sub);
					cur_sub = NULL;
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
				new_event->when = date;
				new_event->sub_mgmt = EVENT_HDL_SUB_MGMT_ASYNC(cur_sub);
				if (data) {
					/* if this fails, please adjust EVENT_HDL_ASYNC_EVENT_DATA in
					 * event_hdl-t.h file or consider providing dynamic struct members
					 * to reduce overall struct size
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
						async_data->mfree = data->_mfree;
						/* Initialize refcount, we start at 1 to prevent async
						 * data from being freed by an async handler while we
						 * still use it. We will drop the reference when the
						 * publish is over.
						 *
						 * (first use, atomic operation not required)
						 */
						async_data->refcount = 1;
					}
					new_event->_data = async_data;
					new_event->data = async_data->data;
					/* increment refcount because multiple hdls could
					 * use the same async_data
					 */
					HA_ATOMIC_INC(&async_data->refcount);
				} else {
					new_event->_data = NULL;
					new_event->data = NULL;
				}

				/* appending new event to event hdl queue */
				MT_LIST_INIT(&new_event->mt_list);
				HA_ATOMIC_INC(&cur_sub->hdl.async_equeue->size);
				MT_LIST_APPEND(&cur_sub->hdl.async_equeue->head, &new_event->mt_list);

				/* wake up the task */
				event_hdl_task_wakeup(cur_sub->hdl.async_task);
			} /* end async mode */
		} /* end hdl should be notified */
	} /* end mt_list */
	if (async_data) {
		/* we finished publishing, drop the reference on async data */
		_event_hdl_async_data_drop(async_data);
	} else {
		/* no async subscribers, we are responsible for calling the data
		 * member freeing function if it was provided
		 */
		if (data && data->_mfree)
			data->_mfree(data->_ptr);
	}
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

void event_hdl_sub_list_init(event_hdl_sub_list *sub_list)
{
	BUG_ON(!sub_list); /* unexpected, global sublist is managed internally */
	MT_LIST_INIT(&sub_list->head);
	MT_LIST_APPEND(&known_event_hdl_sub_list, &sub_list->known);
}

/* internal function, assumes that sub_list ptr is always valid */
static void _event_hdl_sub_list_destroy(event_hdl_sub_list *sub_list)
{
	struct event_hdl_sub *cur_sub;
	struct mt_list back;

	MT_LIST_FOR_EACH_ENTRY_UNLOCKED(cur_sub, &sub_list->head, mt_list, back) {
		/* remove cur elem from list and free it */
		_event_hdl_unsubscribe(cur_sub);
		cur_sub = NULL;
	}
}

/* when a subscription list is no longer used, call this
 * to do the cleanup and make sure all related subscriptions are
 * safely ended according to their types
 */
void event_hdl_sub_list_destroy(event_hdl_sub_list *sub_list)
{
	BUG_ON(!sub_list); /* unexpected, global sublist is managed internally */
	if (!MT_LIST_DELETE(&sub_list->known))
		return; /* already destroyed */
	_event_hdl_sub_list_destroy(sub_list);
}

/* config parser for global "tune.events.max-events-at-once" */
static int event_hdl_parse_max_events_at_once(char **args, int section_type, struct proxy *curpx,
                                              const struct proxy *defpx, const char *file, int line,
                                              char **err)
{
	int arg = -1;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) != 0)
		arg = atoi(args[1]);

	if (arg < 1 || arg > 10000) {
		memprintf(err, "'%s' expects an integer argument between 1 and 10000.", args[0]);
		return -1;
	}

	event_hdl_tune.max_events_at_once = arg;
	return 0;
}

/* config keyword parsers */
static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.events.max-events-at-once", event_hdl_parse_max_events_at_once },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);

INITCALL0(STG_INIT, event_hdl_init);
