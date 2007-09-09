#include <stdio.h>
#include <common/sessionhash.h>

int main(int argc, char *argv[])
{
	appsess *a, *b, *c, *d, *tmp;
	struct appsession_hash h;
	int i;

	a = malloc(sizeof(appsess));
	b = malloc(sizeof(appsess));
	c = malloc(sizeof(appsess));
	d = malloc(sizeof(appsess));

	a->sessid = "abcdefg";
	b->sessid = "2c";
	c->sessid = "pe";
	d->sessid = "abbbbbccccb";

	appsession_hash_init(&h, (void (*)())free);
	appsession_hash_dump(&h);
	appsession_hash_insert(&h, a);
	appsession_hash_insert(&h, b);
	appsession_hash_insert(&h, c);
	appsession_hash_insert(&h, d);

	appsession_hash_dump(&h);

	printf("a:     %p\n", a);
	printf("b:     %p\n", b);
	printf("c:     %p\n", c);
	printf("d:     %p\n", d);
	printf("-------------\n");
	printf("a:     %p\n", appsession_hash_lookup(&h, "abcdefg"));
	printf("b:     %p\n", appsession_hash_lookup(&h, "2c"));
	printf("c:     %p\n", appsession_hash_lookup(&h, "pe"));
	printf("d:     %p\n", appsession_hash_lookup(&h, "abbbbbccccb"));
	printf("null:  %p\n", appsession_hash_lookup(&h, "non existant"));


	appsession_hash_remove(&h, c);
	appsession_hash_remove(&h, d);

	appsession_hash_dump(&h);

	printf("-- remove c,d\n");
	printf("a:     %p\n", appsession_hash_lookup(&h, "abcdefg"));
	printf("b:     %p\n", appsession_hash_lookup(&h, "2c"));
	printf("c:     %p\n", appsession_hash_lookup(&h, "pe"));
	printf("d:     %p\n", appsession_hash_lookup(&h, "abbbbbccccb"));
	printf("null:  %p\n", appsession_hash_lookup(&h, "non existant"));

	appsession_hash_destroy(&h);
}
