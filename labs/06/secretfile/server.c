// ----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         19.03.2021
// Description:  Server code for secretfile program
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"

// Function prototypes
static void waitForConnection(int sfd, struct sockaddr_in *addr);
static int createSocket(struct sockaddr_in *addr);
static void handleClientRequest(int cfd, struct sockaddr_in *addr);
static char fpub[] = "/tmp/public.txt";
static char fsec[] = "/tmp/secret.txt";

//-----------------------------------------------------------------------------
// Main function of server.
// Creates a socket and waits for incoming connections.
//-----------------------------------------------------------------------------
int main(void) {
  int sfd = -1;
  struct sockaddr_in addr = {AF_INET, htons(PORT), INADDR_ANY};
  
  printf("%s%s", INFO, "Starting server...\n");
  printf("%s%s%d%s", INFO, "Communication up. Listen on port ", PORT, "...\n");
  sfd = createSocket(&addr);
  printf("%s%s", INFO, "Wait for clients...\n");
  waitForConnection(sfd, &addr);
  
  return 0;
}

//-----------------------------------------------------------------------------
// This function waits for a connection and calls handleClientConnection
// after a client has connected. 
//-----------------------------------------------------------------------------
void waitForConnection(int sfd, struct sockaddr_in *addr) {
  int cfd, addrlen = sizeof(*addr);

  while((cfd = accept(sfd, (struct sockaddr*)addr, (unsigned*)&addrlen)) > 0) {
    handleClientRequest(cfd, addr);
  }
}

//-----------------------------------------------------------------------------
// This function handles a request by a client. First, the message from the 
// client is read. Then, a response is sent back to the client. A part of the 
// response is read from a file (fpub). Finally, the connection is closed.
//-----------------------------------------------------------------------------
void handleClientRequest(int cfd, struct sockaddr_in *addr) {
  char *host = (char*)inet_ntoa(addr->sin_addr); // Gets IP address of client
  char *file = fpub;
  char message[MSG_SIZE];

  // Print that a connection was established
  printf("%s%s%s%s", INFO, "Client ", host, " connected...\n");

  // Read message from client
  char buf[BUF_SIZE];
  int pos = 0, count = recv(cfd, buf, BUF_SIZE, 0);
  while(count > 0) {
    if(memccpy(message+pos, buf, '\0', count) == NULL) {
      pos += count;
      count = recv(cfd, buf, BUF_SIZE, 0);
    } else {
      count = 0;
    }
  }
  printf("%s%s%s%s", INFO, "Message received from client ", host,"...\n");

  // Send response to client (content of file + message)
  FILE *pubfd = fopen(file, "r");
  if(pubfd != NULL) {
    while((count = fread(buf, 1, BUF_SIZE, pubfd)) > 0 ) {
      send(cfd, buf, count, 0);
    }
    fclose(pubfd);
  } else {
    printf("%s%s", ERROR, "Error opening file...\n");
  }
  send(cfd, message, strlen(message)+1, 0);
  printf("%s%s%s%s", INFO, "Response sent to client ", host, "...\n");

  // Close connection 
  close(cfd);
  printf("%s%s%s%s", INFO, "Client ", host, " disconnected...\n");
}

//-----------------------------------------------------------------------------
// Creates a blocking socket and returns the socket descriptor.
//-----------------------------------------------------------------------------
int createSocket(struct sockaddr_in *addr) {
  int sfd=-1, z=1;
  if((sfd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    printf("%s%s",ERROR, "Cannot setup socket.\n");
    exit(-1);
  }

  setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, NULL, 0);
  if(bind(sfd, (struct sockaddr*)addr, sizeof(*addr)) < 0) {
    printf("%s%s", ERROR, "Bind failed.\n");
    close(sfd);
    exit(-1);
  }

  if(listen(sfd, 20) < 0) {
    printf("%s%s", ERROR, "Listen failed.\n");
    close(sfd);
    exit(-1);
  }
  return sfd;
}
