/*
 * include/haproxy/event_hdl-t.h
 * event handlers management definitions
 *
 * Copyright 2022 HAProxy Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_EVENT_HDL_T_H
# define _HAPROXY_EVENT_HDL_T_H

#include <stdint.h>
#include <sys/time.h>

#include <haproxy/api-t.h>

/* event data struct are defined as followed */
struct event_hdl_cb_data_template {
	struct {
		/* safe data can be safely used from both
		 * sync and async handlers
		 * data consistency is guaranteed
		 */
	} safe;
	struct {
		/* unsafe data may only be used from sync handlers:
		 * in async mode, data consistency cannot be guaranteed
		 * and unsafe data may already be stale, thus using
		 * it is highly discouraged because it
		 * could lead to undefined behavior (UAF, null dereference...)
		 */
	} unsafe;
};

/* event_hdl tunables */
struct event_hdl_tune {
	unsigned int max_events_at_once;
};

/* FIXME: adjust if needed! Should be large enough
 * to support every struct event_hdl_cb_data_x types
 * BUG_ON check in publish/async_mode and static assert
 * in EVENT_HDL_CB_DATA will ensure this
 */
#define EVENT_HDL_ASYNC_EVENT_DATA	(768)
/* used internally to store a single copy of event data when dealing with
 * async handlers.
 * The same copy can be provided to multiple handlers to prevent memory waste:
 * refcount is used to keep track of references so that
 * data can be freed when not used anymore
 */
typedef void (*event_hdl_data_free)(const void *data);
struct event_hdl_async_event_data
{
	/* internal storage */
	char data[EVENT_HDL_ASYNC_EVENT_DATA];
	/* user-provided free function if event data relies on
	 * dynamic members that require specific cleanup
	 */
	event_hdl_data_free mfree;
	uint32_t refcount;
};

/* type for storing event subscription type */
struct event_hdl_sub_type
{
	/* up to 256 families, non cumulative, adjust if needed */
	uint8_t family;
	/* up to 16 sub types using bitmasks, adjust if needed */
	uint16_t subtype;
};

struct event_hdl_sub_list_head {
	struct mt_list head;
	struct mt_list known; /* api uses this to track known subscription lists */
};

/* event_hdl_sub_list is an alias (please use this for portability) */
typedef struct event_hdl_sub_list_head event_hdl_sub_list;

struct event_hdl_async_equeue_head {
	struct mt_list head;
	uint32_t size; /* near realtime size, not fully synced with head (to be used as a hint) */
};

/* event_hdl_async_equeue is an alias to mt_list (please use this for portability) */
typedef struct event_hdl_async_equeue_head event_hdl_async_equeue;

/* subscription mgmt from event */
struct event_hdl_sub_mgmt
{
	/* manage subscriptions from event
	 * this must not be used directly because locking might be required
	 */
	struct event_hdl_sub *this;
	/* safe functions than can be used from event context (sync and async mode) */
	struct event_hdl_sub_type (*getsub)(const struct event_hdl_sub_mgmt *);
	int (*resub)(const struct event_hdl_sub_mgmt *, struct event_hdl_sub_type);
	void (*unsub)(const struct event_hdl_sub_mgmt *);
};

/* single event structure pushed into async event queue
 * used by tasks async handlers
 */
struct event_hdl_async_event
{
	struct mt_list				mt_list;
	struct event_hdl_sub_type		type;
	/* data wrapper - should not be used directly */
	struct event_hdl_async_event_data	*_data;
	/* for easy data access,
	 * points to _data->data if data is available
	 */
	void					*data;
	void	 				*private;
	struct timeval				when;
	struct event_hdl_sub_mgmt		sub_mgmt;
};

/* internal structure provided to function event_hdl_publish()
 * It contains ptr to data relevant to the event
 */
struct event_hdl_cb_data {
	/* internal use: ptr to struct event_hdl_cb_data_type */
	void *_ptr;
	/* internal use: holds actual data size*/
	size_t _size;
	/* user specified freeing function for event_hdl_cb_data_type
	 * struct members
	 */
	event_hdl_data_free _mfree;
};

/* struct provided to event_hdl_cb_* handlers
 * contains data related to the event
 * that triggered the handler
 */
struct event_hdl_cb
{
	/* event type */
	struct event_hdl_sub_type	e_type;
	/* event data */
	void				*e_data;
	/* manage the subscription responsible for handing the event to us */
	const struct event_hdl_sub_mgmt	*sub_mgmt;

	/* may be used by sync event handler to ensure
	 * it runs in sync mode, and thus is eligible to access unsafe data.
	 * This could save the day when users are copy-pasting function
	 * logic from a sync handler to an async handler without
	 * taking appropriate precautions and unsafe accesses are performed.
	 * (See EVENT_HDL_ASSERT_SYNC macro API helper)
	 */
	uint8_t				_sync;
};

/* prototype for event_hdl_cb_sync function pointer */
typedef void (*event_hdl_cb_sync)(const struct event_hdl_cb *cb, void *private);
/* prototype for event_hdl_cb async function pointer */
typedef void (*event_hdl_cb_async)(const struct event_hdl_cb *cb, void *private);
/* prototype for event_hdl_private_free function pointer */
typedef void (*event_hdl_private_free)(void *private);

/* tasklet forward declaration */
struct tasklet;
/* enum for sync mode */
enum event_hdl_async_mode
{
	EVENT_HDL_ASYNC_MODE_NORMAL = 1,
	EVENT_HDL_ASYNC_MODE_ADVANCED = 2
};

/* event hdl, used when subscribing (and then associated with a subscription) */
struct event_hdl {
	/* optional unique id (hash) for lookup */
	uint64_t			id;
	/* handler debug: origin (initial event subscription calling place) */
	const char			*dorigin;
	/* handler requires async mode:
	 *   EVENT_HDL_ASYNC_MODE_NORMAL            = normal
	 *   EVENT_HDL_ASYNC_MODE_ADVANCED 	    = advanced, single task wakeup
	 */
	uint8_t				async;

	union {
		event_hdl_cb_sync	sync_ptr; /* if !async */
		event_hdl_cb_async	async_ptr; /* only used if async==1 (normal) */
	};

	/* ptr to async task responsible for consuming events */
	struct tasklet			*async_task;
	/* used by async tasks to consume pending events */
	event_hdl_async_equeue		*async_equeue;
	/* function ptr automatically called by:
	 *   async task when hdl is unregistered and private is no longer referenced
	 *   sync context when unregistering is performed
	 */
	event_hdl_private_free		private_free;
	/* it is not safe to assume that private will not
	 * be used anymore once hdl is unregistered:
	 * with async handlers, private could still be referenced
	 * in pending events to be consumed later by the task (by design).
	 * If freeing private is needed, you must provide async_private_free
	 * function pointer when registering.
	 * It will be called when private is no longer used
	 * after unregistering hdl to perform private cleanup.
	 * (please use this even in sync mode so that subscription
	 * can easily be turned into async mode later without breaking stuff)
	 */
	void				*private;
};

/* flags for event_hdl_sub struct (32 bits) */
#define EHDL_SUB_F_PAUSED        0x0001  /* subscription will temporarily ignore events */

/* list elem: subscription (handler subscribed to specific events)
 */
struct event_hdl_sub {
	struct mt_list			mt_list;
	/* event type subscription */
	struct event_hdl_sub_type	sub;
	uint32_t                        flags;
	/* event handler */
	struct event_hdl		hdl;
	/* used to guarantee that END event will be delivered
	 * (memory is allocated when registering, no memory failure can occur at runtime)
	 */
	struct event_hdl_async_event 	*async_end;
	/* > 0 : subscription is referenced, don't free yet
	 * use atomic OPS to write and read from it
	 */
	uint32_t			refcount;
	/* TODO: atomic_call_counter for stats?! */
};

#define ESUB_INDEX(n)				(1 << (n - 1))

#define EVENT_HDL_SUB_TYPE(_family, _type)	((struct event_hdl_sub_type){ .family = _family, .subtype = ESUB_INDEX(_type) })
#define EVENT_HDL_SUB_FAMILY(_family)		((struct event_hdl_sub_type){ .family = _family, .subtype = ~0 })

#define EVENT_HDL_SUB_NONE			((struct event_hdl_sub_type){ .family = 0, .subtype = 0})
/* for async tasks: subscription is ending */
#define EVENT_HDL_SUB_END			((struct event_hdl_sub_type){ .family = 0, .subtype = 1})

/*	---------------------------------------        */

/* user defined event types are listed here
 * please reflect any change in these macros in the subtype map
 * defined below that is used to perform string to event type and
 * event type to string conversions
 */

/* SERVER FAMILY, provides event_hdl_cb_data_server struct
 * (will be defined in haproxy/server-t.h)
 */
#define EVENT_HDL_SUB_SERVER                            EVENT_HDL_SUB_FAMILY(1)
#define EVENT_HDL_SUB_SERVER_ADD                        EVENT_HDL_SUB_TYPE(1,1)
#define EVENT_HDL_SUB_SERVER_DEL                        EVENT_HDL_SUB_TYPE(1,2)
#define EVENT_HDL_SUB_SERVER_UP                         EVENT_HDL_SUB_TYPE(1,3)
#define EVENT_HDL_SUB_SERVER_DOWN                       EVENT_HDL_SUB_TYPE(1,4)
/* server state change */
#define EVENT_HDL_SUB_SERVER_STATE                      EVENT_HDL_SUB_TYPE(1,5)
/* server admin change */
#define EVENT_HDL_SUB_SERVER_ADMIN                      EVENT_HDL_SUB_TYPE(1,6)
/* server check-related (agent or health) event */
#define EVENT_HDL_SUB_SERVER_CHECK                      EVENT_HDL_SUB_TYPE(1,7)
/* server inet addr (addr:svc_port tuple) change event */
#define EVENT_HDL_SUB_SERVER_INETADDR                   EVENT_HDL_SUB_TYPE(1,8)

/* PAT_REF family, only published in pat ref subscription list
 * (not published in global subscription list for performance reasons)
 */
#define EVENT_HDL_SUB_PAT_REF                           EVENT_HDL_SUB_FAMILY(2)
#define EVENT_HDL_SUB_PAT_REF_ADD                       EVENT_HDL_SUB_TYPE(2,1)
#define EVENT_HDL_SUB_PAT_REF_DEL                       EVENT_HDL_SUB_TYPE(2,2)
#define EVENT_HDL_SUB_PAT_REF_SET                       EVENT_HDL_SUB_TYPE(2,3)
#define EVENT_HDL_SUB_PAT_REF_COMMIT                    EVENT_HDL_SUB_TYPE(2,4)
#define EVENT_HDL_SUB_PAT_REF_CLEAR                     EVENT_HDL_SUB_TYPE(2,5)

/*	---------------------------------------        */

/* Please reflect changes above in event_hdl_sub_type_map defined
 * in event_hdl.c file
 */
struct event_hdl_sub_type_map {
	const char *name;
	struct event_hdl_sub_type type;
};

#endif /* _HAPROXY_EVENT_HDL_T_H */
