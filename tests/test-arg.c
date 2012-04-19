#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proto/arg.h"

int main(int argc, char **argv)
{
	int nbargs, err_arg, mask;
	struct arg *argp;
	char *err_msg = NULL;
	const char *err_ptr = NULL;

	if (argc < 2) {
		printf("Usage: %s arg_list [arg_mask]\n"
		       "       mask defaults to 0x86543290\n"
		       "   eg: %s 10k,+20,Host,1.2.3.4,24,::5.6.7.8,120s\n", *argv, *argv);
		return 1;
	}

	mask = ARG7(0,SIZE,SINT,STR,IPV4,MSK4,IPV6,TIME);
	if (argc >= 3)
		mask = atoll(argv[2]);

	printf("Using mask=0x%08x\n", mask);
	nbargs = make_arg_list(argv[1], strlen(argv[1]), mask,
			       &argp, &err_msg, &err_ptr, &err_arg);

	printf("nbargs=%d\n", nbargs);
	if (nbargs < 0) {
		printf("err_msg=%s\n", err_msg); free(err_msg);
		printf("err_ptr=%s (str+%d)\n", err_ptr, err_ptr - argv[1]);
		printf("err_arg=%d\n", err_arg);
		return 1;
	}

	if (nbargs > 0) {
		int arg;

		for (arg = 0; arg < nbargs; arg++)
			printf("arg %d: type=%d, int=0x%08x\n",
			       arg, argp[arg].type, *(int*)&argp[arg].data.uint);
	}
	return 0;
}
