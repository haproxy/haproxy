/*
 * experimental weighted round robin scheduler - (c) 2007 willy tarreau.
 *
 * This filling algorithm is excellent at spreading the servers, as it also
 * takes care of keeping the most uniform distance between occurrences of each
 * server, by maximizing this distance. It reduces the number of variables
 * and expensive operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include "eb32tree.h"

struct srv {
	struct eb32_node node;
	struct eb_root *tree; // we want to know where the server is
	int num;
	int w; /* weight */
	int next, last;
	int rem;
} *srv;

/* those trees represent a sliding window of 3 time frames */
struct eb_root tree_0 = EB_ROOT;
struct eb_root tree_1 = EB_ROOT;
struct eb_root tree_2 = EB_ROOT;

struct eb_root *init_tree; /* receives positions 0..sw-1 */
struct eb_root *next_tree; /* receives positions >= 2sw */

int nsrv;       /* # of servers */
int nsw, sw;    /* sum of weights */
int p;          /* current position, between sw..2sw-1 */

/* queue a server in the weights tree */
void queue_by_weight(struct eb_root *root, struct srv *s) {
	s->node.key = 255 - s->w;
	eb32_insert(root, &s->node);
	s->tree = root;
}

/* queue a server in the weight tree <root>, except if its weight is 0 */
void queue_by_weight_0(struct eb_root *root, struct srv *s) {
	if (s->w) {
		s->node.key = 255 - s->w;
		eb32_insert(root, &s->node);
		s->tree = root;
	} else {
		s->tree = NULL;
	}
}

static inline void dequeue_srv(struct srv *s) {
	eb32_delete(&s->node);
}

/* queues a server into the correct tree depending on ->next */
void put_srv(struct srv *s) {
	if (s->w <= 0 ||
	    s->next >= 2*sw ||    /* delay everything which does not fit into the window */
	    s->next >= sw+nsw) {  /* and everything which does not fit into the theorical new window */
		/* put into next tree */
		s->next -= sw; // readjust next in case we could finally take this back to current.
		queue_by_weight_0(next_tree, s);
	} else {
		// The overflow problem is caused by the scale we want to apply to user weight
		// to turn it into effective weight. Since this is only used to provide a smooth
		// slowstart on very low weights (1), it is a pure waste. Thus, we just have to
		// apply a small scaling factor and warn the user that slowstart is not very smooth
		// on low weights.
		// The max key is about ((scale*maxw)*(scale*maxw)*nbsrv)/ratio  (where the ratio is
		// the arbitrary divide we perform in the examples above). Assuming that ratio==scale,
		// this translates to maxkey=scale*maxw^2*nbsrv, so
		//    max_nbsrv=2^32/255^2/scale ~= 66051/scale
		// Using a scale of 16 is enough to support 4000 servers without overflow, providing
		// 6% steps during slowstart.

		s->node.key = 256 * s->next + (16*255 + s->rem - s->w) / 16;

		/* check for overflows */
		if ((int)s->node.key < 0)
			printf(" OV: srv=%p w=%d rem=%d next=%d key=%d", s, s->w, s->rem, s->next, s->node.key);
		eb32_insert(&tree_0, &s->node);
		s->tree = &tree_0;
	}
}

/* prepares a server when extracting it from the init tree */
static inline void get_srv_init(struct srv *s) {
	s->next = s->rem = 0;
}

/* prepares a server when extracting it from the next tree */
static inline void get_srv_next(struct srv *s) {
	s->next += sw;
}

/* prepares a server when extracting it from the next tree */
static inline void get_srv_down(struct srv *s) {
	s->next = p;
}

/* prepares a server when extracting it from its tree */
void get_srv(struct srv *s) {
	if (s->tree == init_tree) {
		get_srv_init(s);
	}
	else if (s->tree == next_tree) {
		get_srv_next(s);
	}
	else if (s->tree == NULL) {
		get_srv_down(s);
	}
}


/* return next server from the current tree, or a server from the init tree
 * if appropriate. If both trees are empty, return NULL.
 */
struct srv *get_next_server() {
	struct eb32_node *node;
	struct srv *s;

	node = eb32_first(&tree_0);
	s = eb32_entry(node, struct srv, node);
	
	if (!node || s->next > p) {
		/* either we have no server left, or we have a hole */
		struct eb32_node *node2;
		node2 = eb32_first(init_tree);
		if (node2) {
			node = node2;
			s = eb32_entry(node, struct srv, node);
			get_srv_init(s);
			if (s->w == 0)
				node = NULL;
			s->node.key = 0; // do not display random values
		}
	}
	if (node)
		return s;
	else
		return NULL;
}

void update_position(struct srv *s) {
	//if (s->tree == init_tree) {
	if (!s->next) {
		// first time ever for this server
		s->last = p;
		s->next = p + nsw / s->w;
		s->rem += nsw % s->w;

		if (s->rem >= s->w) {
			s->rem -= s->w;
			s->next++;
		}
	} else {
		s->last = s->next;  // or p ?
		//s->next += sw / s->w;
		//s->rem += sw % s->w;
		s->next += nsw / s->w;
		s->rem += nsw % s->w;

		if (s->rem >= s->w) {
			s->rem -= s->w;
			s->next++;
		}
	}
}


/* switches trees init_tree and next_tree. init_tree should be empty when
 * this happens, and next_tree filled with servers sorted by weights.
 */
void switch_trees() {
	struct eb_root *swap;
	swap = init_tree;
	init_tree = next_tree;
	next_tree = swap;
	sw = nsw;
	p = sw;
}

main(int argc, char **argv) {
	int conns;
	int i;

	struct srv *s;

	argc--; argv++;
	nsrv = argc;

	if (!nsrv)
		exit(1);

	srv  = calloc(nsrv, sizeof(struct srv));
   
	sw = 0;
	for (i = 0; i < nsrv; i++) {
		s = &srv[i];
		s->num = i;
		s->w = atol(argv[i]);
		sw += s->w;
	}

	nsw = sw;

	init_tree = &tree_1;
	next_tree = &tree_2;

	/* and insert all the servers in the PREV tree */
	/* note that it is required to insert them according to
	 * the reverse order of their weights.
	 */
	printf("---------------:");
	for (i = 0; i < nsrv; i++) {
		s = &srv[i];
		queue_by_weight_0(init_tree, s);
		printf("%2d", s->w);
	}
	printf("\n");

	p = sw; // time base of current tree
	conns = 0;
	while (1) {
		struct eb32_node *node;

		printf("%08d|%06d: ", conns, p);

		/* if we have en empty tree, let's first try to collect weights
		 * which might have changed.
		 */
		if (!sw) {
			if (nsw) {
				sw = nsw;
				p = sw;
				/* do not switch trees, otherwise new servers (from init)
				 * would end up in next.
				 */
				//switch_trees();
				//printf("bla\n");
			}
			else
				goto next_iteration;
		}

		s = get_next_server();
		if (!s) {
			printf("----------- switch (empty) -- sw=%d -> %d ---------\n", sw, nsw);
			switch_trees();
			s = get_next_server();
			printf("%08d|%06d: ", conns, p);

			if (!s)
				goto next_iteration;
		}
		else if (s->next >= 2*sw) {
			printf("ARGGGGG! s[%d].next=%d, max=%d\n", s->num, s->next, 2*sw-1);
		}

		/* now we have THE server we want to put at this position */
		for (i = 0; i < s->num; i++) {
			if (srv[i].w > 0)
				printf(". ");
			else
				printf("_ ");
		}
		printf("# ");
		for (i = s->num + 1; i < nsrv; i++) {
			if (srv[i].w > 0)
				printf(". ");
			else
				printf("_ ");
		}
		printf("  : ");

		printf("s=%02d v=%04d w=%03d n=%03d r=%03d ",
		       s->num, s->node.key, s->w, s->next, s->rem);

		update_position(s);
		printf(" | next=%03d, rem=%03d ", s->next, s->rem);

		if (s->next >= sw * 2) {
			dequeue_srv(s);
			//queue_by_weight(next_tree, s);
			put_srv(s);
			printf(" => next (w=%d, n=%d) ", s->w, s->next);
		}
		else {
			printf(" => curr ");

			//s->node.key = s->next;
			/* we want to ensure that in case of conflicts, servers with
			 * the highest weights will get served first. Also, we still
			 * have the remainder to see where the entry expected to be
			 * inserted.
			 */
			//s->node.key = 256 * s->next + 255 - s->w;
			//s->node.key = sw * s->next + sw / s->w;
			//s->node.key = sw * s->next + s->rem;  /// seems best (check with filltab15) !

			//s->node.key = (2 * sw * s->next) + s->rem + sw / s->w;

			/* FIXME: must be optimized */
			dequeue_srv(s);
			put_srv(s);
			//eb32i_insert(&tree_0, &s->node);
			//s->tree = &tree_0;
		}

	next_iteration:
		p++;
		conns++;
		if (/*conns == 30*/ /**/random()%100 == 0/**/) {
			int w = /*20*//**/random()%4096/**/;
			int num = /*1*//**/random()%nsrv/**/;
			struct srv *s = &srv[num];

			nsw = nsw - s->w + w;
			//sw=nsw;

			if (s->tree == init_tree) {
				printf(" -- chgwght1(%d): %d->%d, n=%d --", s->num, s->w, w, s->next);
				printf("(init)");
				s->w = w;
				dequeue_srv(s);
				queue_by_weight_0(s->tree, s);
			}
			else if (s->tree == NULL) {
				printf(" -- chgwght2(%d): %d->%d, n=%d --", s->num, s->w, w, s->next);
				printf("(down)");
				s->w = w;
				dequeue_srv(s);
				//queue_by_weight_0(init_tree, s);
				get_srv(s);
				s->next = p + (nsw + sw - p) / s->w;
				put_srv(s);
			}
			else {
				int oldnext;

				/* the server is either active or in the next queue */
				get_srv(s);
				printf(" -- chgwght3(%d): %d->%d, n=%d, sw=%d, nsw=%d --", s->num, s->w, w, s->next, sw, nsw);

				oldnext = s->next;
				s->w = w;

				/* we must measure how far we are from the end of the current window
				 * and try to fit their as many entries as should theorically be.
				 */

				//s->w = s->w * (2*sw - p) / sw;
				if (s->w > 0) {
					int step = (nsw /*+ sw - p*/) / s->w;
					s->next = s->last + step;
					s->rem = 0;
					if (s->next > oldnext) {
						s->next = oldnext;
						printf(" aaaaaaa ");
					}

					if (s->next < p + 2) {
						s->next = p + step;
						printf(" bbbbbb ");
					}
				} else {
					printf(" push -- ");
					/* push it into the next tree */
					s->w = 0;
					s->next = p + sw;
				}


				dequeue_srv(s);
				printf(" n=%d", s->next);
				put_srv(s);
			}
		}

		printf("\n");

		if (0 && conns % 50000 == 0) {
			printf("-------- %-5d : changing all weights ----\n", conns);

			for (i = 0; i < nsrv; i++) {
				int w = i + 1;
				s = &srv[i];
				nsw = nsw - s->w + w;
				s->w = w;
				dequeue_srv(s);
				queue_by_weight_0(next_tree, s); // or init_tree ?
			}
		}

	}
}

