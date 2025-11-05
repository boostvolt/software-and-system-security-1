// ----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         19.03.2021
// Description:  Program code for login program
//-----------------------------------------------------------------------------

#define USERS 3
#define INPUT_MAX 64

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int doLogin(char usernames[][8], char passwords[][8]);

//-----------------------------------------------------------------------------
// Main function. Asks the user to login and, if login is successful, grants
// simulated terminal access.
//-----------------------------------------------------------------------------
int main(int argc, char *argv[]) {
  char usernames[USERS][8] = {"root", "john", "tom"};       // There are 3 registered users...
  char passwords[USERS][8] = {"master", "doe", "qwertz"};   // ... with their passwords
  char* command = malloc(INPUT_MAX);
  
  while(1) {
    if (doLogin(usernames, passwords)) {
      printf("Login successful, terminal access granted, enter 'exit' to exit\n");
      while (1) {
        printf("$> ");
        fgets(command, INPUT_MAX, stdin);
        command[strlen(command)-1] = 0;   // remove newline character
        if (!strcmp(command, "exit")) {
          break;
        }
      }
    } 
  }
  return 0;
}


//-----------------------------------------------------------------------------
// Asks the user to enter username and password and compares to valid usernames
// and passwords received as parameters. If login is successful, return 1.
// Otherwise, display a message and return 0.
//-----------------------------------------------------------------------------
int doLogin(char usernames[][8], char passwords[][8]) {
  char* username = malloc(INPUT_MAX);
  char* password = malloc(INPUT_MAX);
  printf("Enter username: ");
  fgets(username, INPUT_MAX, stdin);
  username[strlen(username)-1] = 0;   // remove newline character
  printf("Enter password: ");
  fgets(password, INPUT_MAX, stdin);
  password[strlen(password)-1] = 0;   // remove newline character
  for (int i=0; i<USERS; i++) {
    if(!strcmp(username, usernames[i]) && !strcmp(password, passwords[i])) {
      free(username);
      free(password);
      return 1;   // Login successful
    }
  }
  printf("Sorry ");   // Login failed
  printf(username);
  printf(", try again\n");
  free(username);
  free(password);
  return 0;
}