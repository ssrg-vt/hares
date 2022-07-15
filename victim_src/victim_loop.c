#include <unistd.h>
#include <stdio.h>
#include <signal.h>

void add_one(int *p){
	printf("Call from add_one function with i value before incrementing : %d\n", *p);
	*p += 2;
	printf("Call from add_one function with i value after incrementing : %d\n", *p);
}

int main(int argc, char **argv)
{
	printf("Starting the main function\n");
	int i = 1;
	printf("Call from main function with i value before add_one call: %d\n", i);
	add_one(&i);
	printf("Call from main function with i value after add_one call: %d\n", i);
	return 0;
}


