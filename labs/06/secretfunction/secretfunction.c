//-----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         19.03.2021
// Description:  Program code for secretfunction program
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>


/* Secret function, can only be called by root */
void secret(void) {
  printf ("Secret function was called!\n");
  exit (0);
}

/* Function with buffer overflow vulnerability */
void normal(char *args) {
  char buff[12];

  memset(buff, 'B', sizeof (buff));
  strcpy(buff, args);
  printf("\nbuff: [%s] (%p)(%zu)\n\n", buff, buff, sizeof(buff));
}


int main(int argc, char *argv[]) {
  int uid;

  uid = getuid();

  if(uid == 0) {
    secret();
  }

  if(argc > 1) {
    printf("Address of secret(): (%p)\n", secret);
    printf("Address of normal(): (%p)\n", normal);

    normal(argv[1]);
  } else {
    printf("No argument!\n");
  }

  return 0;
}
