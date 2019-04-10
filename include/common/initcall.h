/*
 * include/common/initcall.h
 *
 * Initcall management.
 *
 * Copyright (C) 2018 Willy Tarreau - w@1wt.eu
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef _COMMON_INIT_H
#define _COMMON_INIT_H

/* List of known init stages. If others are added, please declare their
 * section at the end of the file below.
 */

/* The principle of the initcalls is to create optional sections in the target
 * program which are made of arrays of structures containing a function pointer
 * and 3 argument pointers. Then at boot time, these sections are scanned in a
 * well defined order to call in turn each of these functions with their
 * arguments. This allows to declare register callbacks in C files without
 * having to export lots of things nor to cross-reference functions. There are
 * several initialization stages defined so that certain guarantees are offered
 * (for example list heads might or might not be initialized, pools might or
 * might not have been created yet).
 *
 * On some very old platforms there is no convenient way to retrieve the start
 * or stop pointer for these sections so there is no reliable way to enumerate
 * the callbacks. When this is the case, as detected when USE_OBSOLETE_LINKER
 * is set, instead of using sections we exclusively use constructors whose name
 * is based on the current line number in the file to guarantee uniqueness.
 * When called, these constructors then add their callback to their respective
 * list. It works as well but slightly inflates the executable's size since
 * code has to be emitted just to register each of these callbacks.
 */

/*
 * Please keep those names short enough, they are used to generate section
 * names, Mac OS X accepts section names up to 16 characters, and we prefix
 * them with i_, so stage name can't be more than 14 characters.
 */
enum init_stage {
	STG_PREPARE = 0,      // preset variables, tables, list heads
	STG_LOCK,             // pre-initialize locks
	STG_ALLOC,            // allocate required structures
	STG_POOL,             // create pools
	STG_REGISTER,         // register static lists (keywords etc)
	STG_INIT,             // subsystems normal initialization
	STG_SIZE              // size of the stages array, must be last
};

/* This is the descriptor for an initcall */
struct initcall {
	void (*const fct)(void *arg1, void *arg2, void *arg3);
	void *arg1;
	void *arg2;
	void *arg3;
#if defined(USE_OBSOLETE_LINKER)
	void *next;
#endif
};


#if !defined(USE_OBSOLETE_LINKER)

#ifdef __APPLE__
#define HA_SECTION(s) __section__("__DATA, i_" # s)
#else
#define HA_SECTION(s) __section__("init_" # s)
#endif

/* Declare a static variable in the init section dedicated to stage <stg>,
 * with an element referencing function <function> and arguments <a1..a3>.
 * <linenum> is needed to deduplicate entries created from a same file. The
 * trick with (stg<STG_SIZE) consists in verifying that stg if a valid enum
 * value from the initcall set, and to emit a warning or error if it is not.
 * The function's type is cast so that it is technically possible to call a
 * function taking other argument types, provided they are all the same size
 * as a pointer (args are cast to (void*)). Do not use this macro directly,
 * use INITCALL{0..3}() instead.
 */
#define __GLOBL1(sym)   __asm__(".globl " #sym)
#define __GLOBL(sym)    __GLOBL1(sym)
#define __DECLARE_INITCALL(stg, linenum, function, a1, a2, a3)     \
        __GLOBL(__start_init_##stg );                              \
	__GLOBL(__stop_init_##stg );                               \
	static const struct initcall *__initcb_##linenum           \
	    __attribute__((__used__,HA_SECTION(stg))) =            \
	        (stg < STG_SIZE) ? &(const struct initcall) {      \
		.fct = (void (*)(void *,void *,void *))function,   \
		.arg1 = (void *)(a1),                              \
		.arg2 = (void *)(a2),                              \
		.arg3 = (void *)(a3),                              \
	} : NULL


#else // USE_OBSOLETE_LINKER

/* Declare a static constructor function to register a static descriptor for
 * stage <stg>, with an element referencing function <function> and arguments
 * <a1..a3>. <linenum> is needed to deduplicate entries created from a same
 * file. The trick with (stg<STG_SIZE) consists in verifying that stg if a
 * valid enum value from the initcall set, and to emit a warning or error if
 * it is not.
 * The function's type is cast so that it is technically possible to call a
 * function taking other argument types, provided they are all the same size
 * as a pointer (args are cast to (void*)). Do not use this macro directly,
 * use INITCALL{0..3}() instead.
 */
#define __DECLARE_INITCALL(stg, linenum, function, a1, a2, a3)     \
__attribute__((constructor)) static void __initcb_##linenum()      \
{                                                                  \
	static struct initcall entry = {                           \
		.fct  = (void (*)(void *,void *,void *))function,  \
		.arg1 = (void *)(a1),                              \
		.arg2 = (void *)(a2),                              \
		.arg3 = (void *)(a3),                              \
	};                                                         \
	if (stg < STG_SIZE) {                                      \
		entry.next = __initstg[stg];                       \
		__initstg[stg] = &entry;                           \
	};                                                         \
}

#endif // USE_OBSOLETE_LINKER

/* This is used to resolve <linenum> to an integer before calling
 * __DECLARE_INITCALL(). Do not use this macro directly, use INITCALL{0..3}()
 * instead.
 */
#define _DECLARE_INITCALL(...) \
	__DECLARE_INITCALL(__VA_ARGS__)

/* This requires that function <function> is called with pointer argument
 * <argument> during init stage <stage> which must be one of init_stage.
 */
#define INITCALL0(stage, function)                                     \
	_DECLARE_INITCALL(stage, __LINE__, function, 0, 0, 0)

/* This requires that function <function> is called with pointer argument
 * <argument> during init stage <stage> which must be one of init_stage.
 */
#define INITCALL1(stage, function, arg1)                               \
	_DECLARE_INITCALL(stage, __LINE__, function, arg1, 0, 0)

/* This requires that function <function> is called with pointer arguments
 * <arg1..2> during init stage <stage> which must be one of init_stage.
 */
#define INITCALL2(stage, function, arg1, arg2)                         \
	_DECLARE_INITCALL(stage, __LINE__, function, arg1, arg2, 0)

/* This requires that function <function> is called with pointer arguments
 * <arg1..3> during init stage <stage> which must be one of init_stage.
 */
#define INITCALL3(stage, function, arg1, arg2, arg3)                   \
	_DECLARE_INITCALL(stage, __LINE__, function, arg1, arg2, arg3)

#if !defined(USE_OBSOLETE_LINKER)
/* Iterate pointer p (of type initcall**) over all registered calls at
 * stage <stg>.
 */
#define FOREACH_INITCALL(p,stg)                                               \
	for ((p) = &(__start_init_##stg); (p) < &(__stop_init_##stg); (p)++)

#else // USE_OBSOLETE_LINKER

#define FOREACH_INITCALL(p,stg)                                               \
	for ((p) = __initstg[stg]; (p); (p) = (p)->next)
#endif // USE_OBSOLETE_LINKER


#if !defined(USE_OBSOLETE_LINKER)
/* Declare a section for stage <stg>. The start and stop pointers are set by
 * the linker itself, which is why they're declared extern here. The weak
 * attribute is used so that we declare them ourselves if the section is
 * empty. The corresponding sections must contain exclusively pointers to
 * make sure each location may safely be visited by incrementing a pointer.
 */
#ifdef __APPLE__
#define DECLARE_INIT_SECTION(stg)                                                   \
	extern __attribute__((__weak__)) const struct initcall *__start_init_##stg __asm("section$start$__DATA$i_" # stg); \
	extern __attribute__((__weak__)) const struct initcall *__stop_init_##stg __asm("section$end$__DATA$i_" # stg)

#else
#define DECLARE_INIT_SECTION(stg)                                                   \
	extern __attribute__((__weak__)) const struct initcall *__start_init_##stg; \
	extern __attribute__((__weak__)) const struct initcall *__stop_init_##stg
#endif

/* Declare all initcall sections here */
DECLARE_INIT_SECTION(STG_PREPARE);
DECLARE_INIT_SECTION(STG_LOCK);
DECLARE_INIT_SECTION(STG_ALLOC);
DECLARE_INIT_SECTION(STG_POOL);
DECLARE_INIT_SECTION(STG_REGISTER);
DECLARE_INIT_SECTION(STG_INIT);

// for use in the main haproxy.c file
#define DECLARE_INIT_STAGES asm("")

/* not needed anymore */
#undef DECLARE_INIT_SECTION

#else // USE_OBSOLETE_LINKER

extern struct initcall *__initstg[STG_SIZE];

// for use in the main haproxy.c file
#define DECLARE_INIT_STAGES struct initcall *__initstg[STG_SIZE]

#endif // USE_OBSOLETE_LINKER

#if !defined(USE_OBSOLETE_LINKER)
/* Run the initcalls for stage <stg>. The test on <stg> is only there to
 * ensure it is a valid initcall stage.
 */
#define RUN_INITCALLS(stg)                                                     \
	do {                                                                   \
		const struct initcall **ptr;                                   \
		if (stg >= STG_SIZE)                                           \
			break;                                                 \
		FOREACH_INITCALL(ptr, stg)                                     \
			(*ptr)->fct((*ptr)->arg1, (*ptr)->arg2, (*ptr)->arg3); \
	} while (0)

#else // USE_OBSOLETE_LINKER

/* Run the initcalls for stage <stg>. The test on <stg> is only there to
 * ensure it is a valid initcall stage.
 */
#define RUN_INITCALLS(stg)                                                     \
	do {                                                                   \
		const struct initcall *ptr;                                    \
		if (stg >= STG_SIZE)                                           \
			break;                                                 \
		FOREACH_INITCALL(ptr, stg)                                     \
			(ptr)->fct((ptr)->arg1, (ptr)->arg2, (ptr)->arg3);     \
	} while (0)

#endif // USE_OBSOLETE_LINKER

#endif /* _COMMON_INIT_H */

/*
 * Local variables:
 *  c-indent-level: 8
 *  c-basic-offset: 8
 * End:
 */
