#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#define USE_THREAD
#include <common/mini-clist.h>

/* Stress test the mt_lists.
 * Compile from the haproxy directory with :
 * cc -Iinclude tests/test-list.c -lpthread -O2 -o test-list
 * The only argument it takes is the number of threads to be used.
 * ./test-list 4
 */

struct mt_list pouet_list = MT_LIST_HEAD_INIT(pouet_list);
#define MAX_ACTION 5000000

__thread unsigned int tid;
struct pouet_lol {
	struct mt_list list_elt;
};

void *thread(void *pouet)
{
	struct pouet_lol *lol;
	struct mt_list *elt1, elt2;
	tid = (uintptr_t)pouet;
	int i = 0;

	for (int i = 0; i < MAX_ACTION; i++) {
		struct pouet_lol *lol;
		struct mt_list *elt1, elt2;
		switch (random() % 4) {
		case 0:
			lol = malloc(sizeof(*lol));
			MT_LIST_INIT(&lol->list_elt);
			MT_LIST_ADD(&pouet_list, &lol->list_elt);
			break;
		case 1:
			lol = malloc(sizeof(*lol));
			MT_LIST_INIT(&lol->list_elt);
			MT_LIST_ADDQ(&pouet_list, &lol->list_elt);
			break;

		case 2:
			lol = MT_LIST_POP(&pouet_list, struct pouet_lol *, list_elt);
			if (lol)
				free(lol);
			break;
		case 3:

			mt_list_for_each_entry_safe(lol, &pouet_list, list_elt, elt1, elt2)

{
				if (random() % 2) {
					MT_LIST_DEL_SAFE(elt1);
					free(lol);
				}
				if (random() % 2) {
					break;
				}
			}
			break;
		default:
			break;
		}
	}
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
