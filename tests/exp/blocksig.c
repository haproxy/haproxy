#include <stdio.h>
#include <signal.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	sigset_t new_sig, old_sig;

	sigfillset(&new_sig);
	sigprocmask(SIG_SETMASK, &new_sig, &old_sig);
	printf("old_sig: %16Lx\n", *(unsigned long long*)&old_sig);
	printf("new_sig: %16Lx\n", *(unsigned long long*)&new_sig);
	
	argc--; argv++;
	return argc ? execvp(*argv, argv) : 0;
}
