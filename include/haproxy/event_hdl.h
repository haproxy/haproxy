/*
 * include/haproxy/event_hdl.h
 * event handlers management
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

#ifndef _HAPROXY_EVENT_HDL_H
# define _HAPROXY_EVENT_HDL_H

#include <haproxy/event_hdl-t.h>
#include <haproxy/list.h>

/* preprocessor trick to extract function calling place
 * __FILE__:__LINE__
 */
#define _EVENT_HDL_CALLING_PLACE2(line) #line
#define _EVENT_HDL_CALLING_PLACE1(line) _EVENT_HDL_CALLING_PLACE2(line)
#define _EVENT_HDL_CALLING_PLACE __FILE__":"_EVENT_HDL_CALLING_PLACE1(__LINE__)

/* ------ PUBLIC EVENT_HDL API ------ */

/* You will find a lot of useful information/comments in this file, but if you're looking
 * for a step by step documentation please check out 'doc/internals/api/event_hdl.txt'
 */

/* Note: API helper macros are used in this file to make event_hdl functions usage
 * simpler, safer and more consistent between sync mode and async mode
 */

/* ======================================= EVENT_HDL_SYNC handlers =====================================
 * must be used only with extreme precautions
 * sync handlers are directly called under the function that published the event.
 * Hence, all the processing done within such function will impact the caller.
 *
 * For this reason, you must be extremely careful when using sync mode, because trying to lock something
 * that is already held by the caller, or depending on something external to the current thread will
 * prevent the caller from running.
 *
 * Please consider using async handlers in this case, they are specifically made to solve this limitation.
 *
 * On the other hand, sync handlers are really useful when you directly depend on callers' provided data
 * (example: pointer to data) or you need to perform something before the caller keeps going.
 * A good example could be a cleanup function that will take care of freeing data, closing fds... related
 * to event data before caller's flow keeps going (interrupting the process while dealing with the event).
 */


/* ===================================== EVENT_HDL_ASYNC handlers ======================================
 * async handlers are run in independent tasks, so that the caller (that published the event) can safely
 * return to its own processing.
 *
 * async handlers may access safe event data safely with guaranteed consistency.
 */


/* ================================ IDENTIFIED vs ANONYMOUS EVENT_HDL  =================================
 * When registering a sync or async event handler, you are free to provide a unique identifier (hash).
 *
 * id can be computed using event_hdl_id function.
 *
 * Not providing an id results in the subscription being considered as anonymous subscription.
 * 0 is not a valid identifier (should be > 0)
 *
 * Identified subscription is guaranteed to be unique for a given subscription list,
 * whereas anonymous subscriptions don't provide such guarantees.
 *
 * Identified subscriptions provide the ability to be later queried or unregistered from external code
 * using dedicated id/hash for the lookups.
 *
 * On the other hand, anonymous subscriptions don't, the only other way to reference an anonymous subscription
 * is to use a subscription pointer.
 *
 */

/* general purpose hashing function when you want to compute
 * an ID based on <scope> x <name>
 * It is your responsibility to make sure <scope> is not used
 * elsewhere in the code (or that you are fine with sharing
 * the scope).
 */
uint64_t event_hdl_id(const char *scope, const char *name);

/* ------ EVENT SUBSCRIPTIONS FUNCTIONS ------ */

/* macro helper:
 * sync version
 *
 * identified subscription
 *
 * <_id>: subscription id that could be used later
 * to perform subscription lookup by id
 * <func>: pointer to 'event_hdl_cb_sync' prototyped function
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> when unsubscription is performed
 */
#define EVENT_HDL_ID_SYNC(_id, func, _private, _private_free)		\
	(struct event_hdl){ .id = _id,					\
			    .dorigin = _EVENT_HDL_CALLING_PLACE,	\
			    .async = 0,					\
			    .sync_ptr = func,				\
			    .private = _private,			\
			    .private_free = _private_free }

/* macro helper:
 * sync version
 *
 * anonymous subscription (no lookup by id)
 *
 * <func>: pointer to 'event_hdl_cb_sync' prototyped function
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> when unsubscription is performed
 */
#define EVENT_HDL_SYNC(func, _private, _private_free)		  	\
	EVENT_HDL_ID_SYNC(0, func, _private, _private_free)

/* macro helper:
 * async version
 *
 * identified subscription
 *
 * <_id>: subscription id that could be used later
 * to perform subscription lookup by id
 * <func>: pointer to 'event_hdl_cb_sync' prototyped function
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> after unsubscription is performed,
 * when no more events can refer to <private>.
 */
#define EVENT_HDL_ID_ASYNC(_id, func, _private, _private_free)		\
	(struct event_hdl){ .id = _id,					\
			    .dorigin = _EVENT_HDL_CALLING_PLACE,	\
			    .async = EVENT_HDL_ASYNC_MODE_NORMAL,	\
			    .async_ptr = func,				\
			    .private = _private,			\
			    .private_free = _private_free }

/* macro helper:
 * async version
 *
 * anonymous subscription (no lookup by id)
 *
 * <func>: pointer to 'event_hdl_cb_sync' prototyped function
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> after unsubscription is performed,
 * when no more events can refer to <private>.
 */
#define EVENT_HDL_ASYNC(func, _private, _private_free)			\
	EVENT_HDL_ID_ASYNC(0, func, _private, _private_free)

/* macro helper:
 * async version
 * same than EVENT_HDL_ID_ASYNC - advanced mode:
 * you directly provide task and event_queue list.
 *
 * identified subscription
 *
 * <_id>: subscription id that could be used later
 * to perform subscription lookup by id
 * <equeue>: pointer to event_hdl_async_event queue where the pending
 * events will be pushed. Cannot be NULL.
 * <task>: pointer to task(let) responsible for consuming the events.
*  Cannot be NULL.
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> after unsubscription is performed,
 * when no more events can refer to <private>.
 */
#define EVENT_HDL_ID_ASYNC_TASK(_id, equeue, task, _private, _private_free)	\
	(struct event_hdl){ .id = _id,						\
			    .dorigin = _EVENT_HDL_CALLING_PLACE,		\
			    .async = EVENT_HDL_ASYNC_MODE_ADVANCED,		\
			    .async_task = (struct tasklet *)task,		\
			    .async_equeue = equeue,				\
			    .private = _private,				\
			    .private_free = _private_free }

/* macro helper:
 * async version
 * same than EVENT_HDL_ASYNC - advanced mode:
 * you directly provide task and event_queue list.
 *
 * anonymous subscription (no lookup by id)
 *
 * <equeue>: pointer to event_hdl_async_event queue where the pending
 * events will be pushed. Cannot be NULL.
 * <task>: pointer to task(let) responsible for consuming the events
 * Cannot be NULL.
 * <_private>: pointer to private data that will be handled to <func>
 * <_private_free>: pointer to 'event_hdl_private_free' prototyped function
 * that will be called with <private> after unsubscription is performed,
 * when no more events can refer to <private>.
 */
#define EVENT_HDL_ASYNC_TASK(equeue, task, _private, _private_free)		\
	EVENT_HDL_ID_ASYNC_TASK(0, equeue, task, _private, _private_free)

/* register a new event subscription in <sub_list>
 * that will handle <e_type> events
 *
 * This function requires you to use
 * EVENT_HDL_(TASK_)(A)SYNC() EVENT_HDL_ID_(TASK_)(A)SYNC() (choose wisely)
 * macro helpers to provide <hdl> argument
 *
 * If <sub_list> is not specified (equals NULL):
 * global subscription list (process wide) will be used.
 *
 * For identified subscriptions (EVENT_HDL_ID_*), the function is safe against
 * concurrent subscriptions attempts with the same ID: the ID will only be
 * inserted once in the list and subsequent attempts will yield an error.
 * However, trying to register the same ID multiple times is considered as
 * an error (no specific error code is returned in this case) so the check should
 * be performed by the caller if it is expected. (The caller must ensure that the ID
 * is unique to prevent the error from being raised)
 *
 * Returns 1 in case of success, 0 in case of failure (invalid argument / memory error)
 */
int event_hdl_subscribe(event_hdl_sub_list *sub_list,
                        struct event_hdl_sub_type e_type, struct event_hdl hdl);

/* same as event_hdl_subscribe, but
 * returns the subscription ptr in case of success
 * or NULL in case of failure
 * subscription refcount is automatically incremented by 1
 * so that ptr remains valid while you use it.
 * You must call event_hdl_drop() when you no longer
 * use it or event_hdl_unsubscribe() to unregister the
 * subscription
 */
struct event_hdl_sub *event_hdl_subscribe_ptr(event_hdl_sub_list *sub_list,
                                              struct event_hdl_sub_type e_type, struct event_hdl hdl);

/* update subscription type:
 * if new type family does not match current family, does nothing
 * only subtype update is supported
 * Returns 1 for SUCCESS and 0 for FAILURE (update not supported)
 */
int event_hdl_resubscribe(struct event_hdl_sub *cur_sub, struct event_hdl_sub_type type);

/* unregister an existing subscription <sub>
 * will automatically call event_hdl_drop()
 */
void event_hdl_unsubscribe(struct event_hdl_sub *sub);

/* decrease subscription refcount by 1
 * use this when you no longer use sub ptr
 * provided by event_hdl_subscribe_ptr or
 * to cancel previous event_hdl_take()
 */
void event_hdl_drop(struct event_hdl_sub *sub);

/* increase subscription refcount by 1
 * event_hdl_drop is needed when ptr
 * is not longer used
 * or event_hdl_unsubscribe to end the subscription
 */
void event_hdl_take(struct event_hdl_sub *sub);

/* ------ EVENT_HDL_LOOKUP: subscription lookup operations from external code ------ */

/* use this function to unregister the subscription <lookup_ip>
 * within <sub_list> list.
 * If <sub_list> is NULL, global subscription list will be used.
 * Returns 1 for SUCCESS and 0 if not found
 */
int event_hdl_lookup_unsubscribe(event_hdl_sub_list *sub_list,
                                 uint64_t lookup_id);

/* use this function to update subscription by <lookup_id> within <sub_list> list
 * if new type family does not match current family, does nothing
 * only subtype update is supported
 * If <sub_list> is NULL, global subscription list will be used.
 * Returns 1 for SUCCESS and 0 if not found or not supported
 */
int event_hdl_lookup_resubscribe(event_hdl_sub_list *sub_list,
                                 uint64_t lookup_id, struct event_hdl_sub_type type);

/* use this function to get a new reference ptr to the subscription
 * identified by <id>
 * or event_hdl_unsubscribe to end the subscription
 * If <sub_list> is NULL, global subscription list will be used.
 * returns NULL if not found
 * returned ptr should be called with event_hdl_drop when no longer used
 */
struct event_hdl_sub *event_hdl_lookup_take(event_hdl_sub_list *sub_list,
                                            uint64_t lookup_id);

/* pause an existing subscription <sub>
 * the subscription will no longer receive events (reversible)
 * This can be reverted thanks to _resume() function
 */
void event_hdl_pause(struct event_hdl_sub *sub);

/* resume an existing subscription <sub>
 * that was previously paused using _pause() function
 */
void event_hdl_resume(struct event_hdl_sub *sub);

/* Same as event_hdl_pause() for identified subscriptions:
 * use this function to pause the subscription <lookup_ip>
 * within <sub_list> list.
 * If <sub_list> is NULL, global subscription list will be used.
 * Returns 1 for SUCCESS and 0 if not found
 */
int event_hdl_lookup_pause(event_hdl_sub_list *sub_list,
                           uint64_t lookup_id);

/* Same as event_hdl_resume() for identified subscriptions:
 * use this function to resume the subscription <lookup_ip>
 * within <sub_list> list.
 * If <sub_list> is NULL, global subscription list will be used.
 * Returns 1 for SUCCESS and 0 if not found
 */
int event_hdl_lookup_resume(event_hdl_sub_list *sub_list,
                            uint64_t lookup_id);

/* ------ PUBLISHING FUNCTIONS ------ */

/* this macro is provided as an internal helper to automatically populate
 * data for fixed length structs as required by event_hdl publish function
 */
#define _EVENT_HDL_CB_DATA_ASSERT(size)					\
	({								\
		/* if this fails to compile				\
		 * it means you need to fix				\
		 * EVENT_HDL_ASYNC_EVENT_DATA				\
		 * size in event_hdl-t.h				\
		 */							\
		__attribute__((unused))					\
		char __static_assert[(size <= EVENT_HDL_ASYNC_EVENT_DATA) ? 1 : -1];\
		(size);							\
	})
#define _EVENT_HDL_CB_DATA(data,size,mfree)				\
	(&(struct event_hdl_cb_data){ ._ptr = data,			\
				      ._size = size,			\
				      ._mfree = mfree })

/* Use this when 'safe' data is completely standalone */
#define EVENT_HDL_CB_DATA(data)						\
	_EVENT_HDL_CB_DATA(data,					\
			   _EVENT_HDL_CB_DATA_ASSERT(sizeof(*data)),	\
			   NULL)
/* Use this when 'safe' data points to dynamically allocated members
 * that require freeing when the event is completely consumed
 * (data in itself may be statically allocated as with
 *  EVENT_HDL_CB_DATA since the publish function will take
 *  care of copying it for async handlers)
 *
 * mfree function will be called with data as argument
 * (or copy of data in async context) when the event is completely
 * consumed (sync and async handlers included). This will give you
 * enough context to perform the required cleanup steps.
 *
 * mfree should be prototyped like this:
 *    void (*mfree)(const void *data)
 */
#define EVENT_HDL_CB_DATA_DM(data, mfree)				\
	_EVENT_HDL_CB_DATA(data,                                        \
			   _EVENT_HDL_CB_DATA_ASSERT(sizeof(*data)),    \
			   mfree)

/* event publishing function
 * this function should be called from anywhere in the code to notify
 * about an <e_type> and provide some relevant <data>
 * that will be provided to subscriptions in <sub_list>
 * that are subscribed to <e_type>.
 * <data> should be provided using EVENT_HDL_CB_DATA helper macro
 *
 * Example:
 * 	struct event_hdl_cb_data_server cb_data;
 *
 *	/...
 *	cb_data initialization
 *	.../
 *
 * 	event_hdl_publish(NULL, EVENT_HDL_SUB_SERVER_UP, EVENT_HDL_CB_DATA(&cb_data));
 */
int event_hdl_publish(event_hdl_sub_list *sub_list,
                      struct event_hdl_sub_type e_type, const struct event_hdl_cb_data *data);

/* ------ MISC/HELPER FUNCTIONS ------ */

/* returns a statically allocated string that is
 * the printable representation of <sub_type>
 * or "N/A" if <sub_type> does not exist
 */
const char *event_hdl_sub_type_to_string(struct event_hdl_sub_type sub_type);

/* returns the internal sub_type corresponding
 * to the printable representation <name>
 * or EVENT_HDL_SUB_NONE if no such event exists
 * (see event_hdl-t.h for the complete list of supported types)
 */
struct event_hdl_sub_type event_hdl_string_to_sub_type(const char *name);

/* Use this from sync hdl to ensure the function is executed
 * in sync mode (and thus unsafe data is safe to use from this ctx)
 * This macro is meant to prevent unsafe data access
 * if code from sync function is copy pasted into
 * async function (or if sync handler is changed
 * to async handler without adapting the code)
 * FIXME: do we BUG_ON, or simply warn and return from the function?
 */
#define EVENT_HDL_ASSERT_SYNC(cb) BUG_ON(!cb->_sync)

/* check if a and b sub types are part of the same family */
static inline int event_hdl_sub_family_equal(struct event_hdl_sub_type a, struct event_hdl_sub_type b)
{
	return (a.family == b.family);
}

/* compares 2 event_hdl_sub_type structs
 * returns 1 if equal, 0 if not equal
 */
static inline int event_hdl_sub_type_equal(struct event_hdl_sub_type a, struct event_hdl_sub_type b)
{
	return (a.family == b.family && a.subtype == b.subtype);
}

/* performs subtraction between A and B event_hdl_sub_type
 */
static inline struct event_hdl_sub_type event_hdl_sub_type_del(struct event_hdl_sub_type a, struct event_hdl_sub_type b)
{
	if (unlikely(!a.family))
		a.family = b.family;
	if (unlikely(a.family != b.family))
		return a;
	a.subtype &= ~b.subtype;

	return a;
}

/* performs addition between A and B event_hdl_sub_type
 */
static inline struct event_hdl_sub_type event_hdl_sub_type_add(struct event_hdl_sub_type a, struct event_hdl_sub_type b)
{
	if (unlikely(!a.family))
		a.family = b.family;
	if (unlikely(a.family != b.family))
		return a;
	a.subtype |= b.subtype;

	return a;
}

/* use this function when you consumed an event in async handler
 * (this will free the event so you must ensure that the event
 * is already removed from the event queue and that you
 * no longer make use of it)
 */
void event_hdl_async_free_event(struct event_hdl_async_event *e);

/* use this for advanced async mode to initialize event queue */
static inline void event_hdl_async_equeue_init(event_hdl_async_equeue *queue)
{
	MT_LIST_INIT(&queue->head);
	queue->size = 0;
}

/* use this for advanced async mode to pop an event from event queue */
static inline struct event_hdl_async_event *event_hdl_async_equeue_pop(event_hdl_async_equeue *queue)
{
	struct event_hdl_async_event *event;

	event = MT_LIST_POP(&queue->head, struct event_hdl_async_event *, mt_list);
	if (event)
		HA_ATOMIC_DEC(&queue->size);
	return event;
}

/* use this for advanced async mode to check if the event queue is empty */
static inline int event_hdl_async_equeue_isempty(event_hdl_async_equeue *queue)
{
	return MT_LIST_ISEMPTY(&queue->head);
}

/* use this for advanced async mode to check if the event queue size */
static inline uint32_t event_hdl_async_equeue_size(event_hdl_async_equeue *queue)
{
	return HA_ATOMIC_LOAD(&queue->size);
}

/* use this to initialize <sub_list> event subscription list */
void event_hdl_sub_list_init(event_hdl_sub_list *sub_list);

/* check if <sub_list> subscriber count is 0 or not */
static inline int event_hdl_sub_list_empty(event_hdl_sub_list *sub_list)
{
	return MT_LIST_ISEMPTY(&sub_list->head);
}

/* use this function when you need to destroy <sub_list>
 * event subscription list
 * All subscriptions will be removed and properly freed according
 * to their types
 */
void event_hdl_sub_list_destroy(event_hdl_sub_list *sub_list);

/* event_hdl tunables */
extern struct event_hdl_tune event_hdl_tune;

#endif /* _HAPROXY_EVENT_HDL_H */
