/*
 * Contribution from Aleksandar Lazic <al-haproxy@none.at>
 *
 * Build with :
 *   gcc -O2 -o test_pools test_pools.c
 * or with dlmalloc too :
 *   gcc -O2 -o test_pools -D USE_DLMALLOC test_pools.c -DUSE_DL_PREFIX dlmalloc.c
 */

#include <sys/time.h>
#include <time.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

static struct timeval timeval_current(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv;
}

static double timeval_elapsed(struct timeval *tv)
{
	struct timeval tv2 = timeval_current();
	return (tv2.tv_sec - tv->tv_sec) + 
	       (tv2.tv_usec - tv->tv_usec)*1.0e-6;
}

#define torture_assert(test, expr, str) if (!(expr)) { \
	printf("failure: %s [\n%s: Expression %s failed: %s\n]\n", \
		test, __location__, #expr, str); \
	return false; \
}

#define torture_assert_str_equal(test, arg1, arg2, desc) \
	if (strcmp(arg1, arg2)) { \
		printf("failure: %s [\n%s: Expected %s, got %s: %s\n]\n", \
		   test, __location__, arg1, arg2, desc); \
		return false; \
	}

/* added pools from haproxy */
#include <stdlib.h>

/*
 * Returns a pointer to an area of <__len> bytes taken from the pool <pool> or
 * dynamically allocated. In the first case, <__pool> is updated to point to
 * the next element in the list.
 */
#define pool_alloc_from(__pool, __len)                      \
({                                                          \
        void *__p;                                          \
        if ((__p = (__pool)) == NULL)                       \
                __p = malloc(((__len) >= sizeof (void *)) ? \
                      (__len) : sizeof(void *));            \
        else {                                              \
                __pool = *(void **)(__pool);                \
        }                                                   \
        __p;                                                \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free_to(__pool, __ptr)             \
({                                              \
        *(void **)(__ptr) = (void *)(__pool);   \
        __pool = (void *)(__ptr);               \
})

/*
 * Returns a pointer to type <type> taken from the
 * pool <pool_type> or dynamically allocated. In the
 * first case, <pool_type> is updated to point to the
 * next element in the list.
 */
#define pool_alloc(type)                                \
({                                                      \
        void *__p;                                      \
        if ((__p = pool_##type) == NULL)                \
                __p = malloc(sizeof_##type);            \
        else {                                          \
                pool_##type = *(void **)pool_##type;	\
        }                                               \
        __p;                                            \
})

/*
 * Puts a memory area back to the corresponding pool.
 * Items are chained directly through a pointer that
 * is written in the beginning of the memory area, so
 * there's no need for any carrier cell. This implies
 * that each memory area is at least as big as one
 * pointer.
 */
#define pool_free(type, ptr)                            \
({                                                      \
        *(void **)ptr = (void *)pool_##type;            \
        pool_##type = (void *)ptr;                      \
})

/*
 * This function destroys a pull by freeing it completely.
 * This should be called only under extreme circumstances.
 */
static inline void pool_destroy(void **pool)
{
	void *temp, *next;
	next = pool;
	while (next) {
		temp = next;
		next = *(void **)temp;
		free(temp);
	}
}

#define sizeof_talloc   1000

/*
  measure the speed of hapx versus malloc
*/
static bool test_speed1(void)
{
        void **pool_talloc = NULL;
	void *ctx = pool_alloc(talloc);
	unsigned count;
	const int loop = 1000;
	int i;
	struct timeval tv;

	printf("test: speed [\nhaproxy-pool VS MALLOC SPEED 2\n]\n");

	tv = timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = pool_alloc_from(pool_talloc, 10 + loop % 100);
			p2 = pool_alloc_from(pool_talloc, strlen("foo bar") + 1);
			strcpy(p2, "foo bar");
			p3 = pool_alloc_from(pool_talloc, 300);
			pool_free_to(pool_talloc,p1);
			pool_free_to(pool_talloc,p3);
			pool_free_to(pool_talloc,p2);
		}
		count += 3 * loop;
	} while (timeval_elapsed(&tv) < 5.0);

	fprintf(stderr, "haproxy : %10.0f ops/sec\n", count/timeval_elapsed(&tv));

        pool_destroy(pool_talloc);

	tv = timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = malloc(10 + loop % 100);
			p2 = malloc(strlen("foo bar") + 1);
			strcpy(p2, "foo bar");
			p3 = malloc(300);
			free(p1);
			free(p2);
			free(p3);
		}
		count += 3 * loop;
	} while (timeval_elapsed(&tv) < 5.0);
	fprintf(stderr, "malloc  : %10.0f ops/sec\n", count/timeval_elapsed(&tv));

#ifdef USE_DLMALLOC
	tv = timeval_current();
	count = 0;
	do {
		void *p1, *p2, *p3;
		for (i=0;i<loop;i++) {
			p1 = dlmalloc(10 + loop % 100);
			p2 = dlmalloc(strlen("foo bar") + 1);
			strcpy(p2, "foo bar");
			p3 = dlmalloc(300);
			dlfree(p1);
			dlfree(p2);
			dlfree(p3);
		}
		count += 3 * loop;
	} while (timeval_elapsed(&tv) < 5.0);
	fprintf(stderr, "dlmalloc: %10.0f ops/sec\n", count/timeval_elapsed(&tv));
#endif

	printf("success: speed1\n");

	return true;
}

int main(void)
{
	bool ret = test_speed1();
	if (!ret)
		return -1;
	return 0;
}
