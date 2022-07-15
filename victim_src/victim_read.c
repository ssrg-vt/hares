#include <unistd.h>
#include <stdio.h>
#include <signal.h>

char *hello = 0x10000;

void sig_handler(int signum){

  //Return type of the handler function should be void
  printf("\nInside handler function\n");
  printf("\nthe value of hello is %d\n", *hello);
  signal(SIGINT,SIG_DFL);
}

int main(int argc, char **argv)
{
	int i = 0;// aux;
//        signal(SIGINT,sig_handler);
	sleep(5);
//	while(1);
	hello += 0xf;
	do {
                printf("Victim about to read a new page @ %p!!!!!!!!!!!!!!\n", hello);
                i++;
                //fprintf(stdout,"Hello world!!\n");
		fprintf(stdout,"%c\n", *hello);
		sleep(5);
		sleep(5);
		hello += 4096;
                if(i%26 == 0)
                    hello = 0x1000f;
	} while (i < 10000);

	return 0;
}
