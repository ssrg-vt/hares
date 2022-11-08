#include <unistd.h>
#include <stdio.h>
#include <signal.h>

volatile char *hello = 0x10000;

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
	//hello += 0xf;
	do {
        printf("Victim about to write a new page @ %p!!!!!!!!!!!!!!\n", hello);
        i++;
        //fprintf(stdout,"Hello world!!\n");
	
	int k = 0;

	sleep(1);
  #if 0
	if(i%2 == 0)
	    *(hello + 0xf) = 'm';
	else
            *(hello + 0xf) = 'b';
  #endif 
  
        //fprintf(stdout,"address %p value %c\n", hello, *(hello+0xf));
        hello += 4096;
       
        if(i % 26 == 0){
            hello = 0x10000;
	      }
	} while (i < 52);

  while(1);
	return 0;
}
