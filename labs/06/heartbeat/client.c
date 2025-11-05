// ----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         19.03.2021
// Description:  Client code for heartbeat program
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "common.h"

unsigned int readPacketHeader(int csd);
void sendPacketHeader(int csd, unsigned int packetContentLength);


//-----------------------------------------------------------------------------
// Main function of client. Creates a connection to the server, sends a
// heartbeat request, and receives the response.
//-----------------------------------------------------------------------------
int main(int argc, char *argv[]) {

  // Check arguments
  if(argc < 4) {
    printf("Usage: client hostname/ip length payload {padding}\n");
    exit(-1);
  }
  int len = atoi(argv[2]);
  if (len < MIN_PAYLOAD_PADDING_SIZE || len > MAX_PAYLOAD_PADDING_SIZE) {
    printf("Length must be between 1 and 65535\n");
    exit(-1);
  }
  unsigned short payloadLength = len;
  if (strlen(argv[3]) < MIN_PAYLOAD_PADDING_SIZE || strlen(argv[3]) > MAX_PAYLOAD_PADDING_SIZE) {
    printf("Payload must contain between 1 and 65535 characters\n");
    exit(-1);
  }
  unsigned char* payload = argv[3];
  unsigned char* padding;
  if (argc > 4) {
    if (strlen(argv[4]) + strlen(payload) > MAX_PAYLOAD_PADDING_SIZE) {
      printf("Padding and paload together must contain between 1 and 65535 characters\n");
      exit(-1);
    } else {
      padding = argv[4];
    }
  } else {
    padding = "";
  }
  
  // Create IP address of server from argument
  struct in_addr iaddr;
  struct hostent *server;
  if(inet_aton(argv[1], &iaddr) > 0) {
    server = gethostbyaddr((char*)&iaddr, sizeof(iaddr), AF_INET);
  } else {
    server = gethostbyname(argv[1]);
  }
  if(server == NULL) {
    printf("Host not found\n");
    exit(-1);
  } 

  // Create socket to connect to server
  struct sockaddr_in addr;
  int sd = socket(PF_INET, SOCK_STREAM, 0);
  if(sd < 0) {
    printf("Cannot create socket\n");
    exit(-1);
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  memcpy(&addr.sin_addr, server->h_addr_list[0], sizeof(addr.sin_addr));

  // Connect to server
  if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    printf("Cannot connect to server\n");
    exit(-1);
  }
  printf("Connection established\n");
  
  // Create and send packet header
  sendPacketHeader(sd, PAYLOAD_LENGTH_SIZE + strlen(payload) + strlen(padding));
   
  // Create and send payload length
  unsigned char payloadLengthBytes[2];
  payloadLengthBytes[0] = (payloadLength >> 8) & 0xff;
  payloadLengthBytes[1] = payloadLength & 0xff;
  send(sd, payloadLengthBytes, 2, 0);   

  // Send payload and padding
  send(sd, payload, strlen(payload), 0);
  send(sd, padding, strlen(padding), 0);
  printf("Heartbeat request sent, length: %lu (%d bytes packet header, %d bytes payload length, %lu bytes payload, %lu bytes padding)\n", 
    PACKET_HEADER_SIZE + PAYLOAD_LENGTH_SIZE + strlen(payload) + strlen(padding), 
    PACKET_HEADER_SIZE, PAYLOAD_LENGTH_SIZE, strlen(payload), strlen(padding));

  // Receive packet header from server
  unsigned int responseLength = readPacketHeader(sd);                  
  printf("Heartbeat response received, length: %d (%d bytes packet header, %d bytes payload length, %d bytes payload)\n", 
    PACKET_HEADER_SIZE + responseLength, PACKET_HEADER_SIZE, PAYLOAD_LENGTH_SIZE, responseLength - PAYLOAD_LENGTH_SIZE);               
  if (responseLength < (PAYLOAD_LENGTH_SIZE + MIN_PAYLOAD_PADDING_SIZE) || 
      responseLength > (PAYLOAD_LENGTH_SIZE + MAX_PAYLOAD_PADDING_SIZE)) {
    printf("Heartbeat response length %d not valid\n", responseLength);
    return 0;
  }

  // Receive response from server and print it
  unsigned char buf[BUF_SIZE];
  int pos = 0;
  int allBytesReceived = 0;
  int count = recv(sd, buf, BUF_SIZE, 0);
  int countPayloadLength = 0;
  printf("Payload received: ");
  while(count > 0 && !allBytesReceived) {
    for (int i=0; i < count; i++) {
      if (countPayloadLength < 2) {
        countPayloadLength++;
      } else {
        printf("%c", buf[i]);
      }
    }
    pos += count;
    if (pos == responseLength) {
      allBytesReceived = 1;
    } else {
      count = recv(sd, buf, BUF_SIZE, 0);
    }
  }
  printf("\n");

  // Close connection
  close(sd);	
  printf("Connection closed\n");  
  return 0;
}
