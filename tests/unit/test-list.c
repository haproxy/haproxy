#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define USE_THREAD
#include <mt_list.h>

/* Stress test for mt_lists. Compile this way:
 *    cc -O2 -o test-list test-list.c -I../include -pthread
 * The only argument it takes is the number of threads to be used.
 * ./test-list 4
 */

struct mt_list pouet_list = MT_LIST_HEAD_INIT(pouet_list);
#define MAX_ACTION 5000000

__thread unsigned int tid;
struct pouet_lol {
	struct mt_list list_elt;
};

/* Fixed RNG sequence to ease reproduction of measurements (will be offset by
 * the thread number).
 */
__thread uint32_t rnd32_state = 2463534242U;

/* Xorshift RNG from http://www.jstatsoft.org/v08/i14/paper */
static inline uint32_t rnd32()
{
        rnd32_state ^= rnd32_state << 13;
        rnd32_state ^= rnd32_state >> 17;
        rnd32_state ^= rnd32_state << 5;
        return rnd32_state;
}

void *thread(void *pouet)
{
	struct pouet_lol *lol;
	struct mt_list elt2;
	tid = (uintptr_t)pouet;
	int i;

	rnd32_state += tid;

	for (i = 0; i < MAX_ACTION; i++) {
		switch (rnd32() % 4) {
		case 0:
			lol = malloc(sizeof(*lol));
			MT_LIST_INIT(&lol->list_elt);
			MT_LIST_TRY_INSERT(&pouet_list, &lol->list_elt);
			break;
		case 1:
			lol = malloc(sizeof(*lol));
			MT_LIST_INIT(&lol->list_elt);
			MT_LIST_TRY_APPEND(&pouet_list, &lol->list_elt);
			break;

		case 2:
			lol = MT_LIST_POP(&pouet_list, struct pouet_lol *, list_elt);
			if (lol)
				free(lol);
			break;
		case 3:
			MT_LIST_FOR_EACH_ENTRY_LOCKED(lol, &pouet_list, list_elt, elt2) {
				if (rnd32() % 2) {
					free(lol);
					lol = NULL;
				}
				if (rnd32() % 2) {
					break;
				}
			}
			break;
		default:
			break;
		}
		if ((i) / (MAX_ACTION/10) != (i+1) / (MAX_ACTION/10))
			printf("%u: %d\n", tid, i+1);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	int nb;
	pthread_t *pth;

	srandom(time(NULL));
	if (argc != 2) {
		printf("Usage: %s <nb_threads>\n", argv[0]);
		exit(1);
	}
	nb = atoi(argv[1]);
#if 0
	if (nb < 2) {
		printf("Need at least 2 threads.\n");
		exit(1);
	}
#endif
	pth = malloc(nb * sizeof(*pth));
	if (pth == NULL) {
		printf("Shot failed to connect.\n");
		exit(1);
	}
	for (int i = 0; i < nb; i++) {
		pthread_create(&pth[i], NULL, thread, (void *)(uintptr_t)i);

	}
	for (int i = 0; i < nb; i++)
		pthread_join(pth[i], NULL);
	return 0;
}
