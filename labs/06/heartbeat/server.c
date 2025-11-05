// ----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         18.03.2021
// Description:  Server code for heartbeat program
// ----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.h"

unsigned char* readRequest(int csd);
void sendResponse(int csd, unsigned char* request);
int createSocket(struct sockaddr_in *addr);
char* simulateSensitiveData();


//-----------------------------------------------------------------------------
// Main function of server. Creates a socket and waits for incoming 
// connections. If a connection is made handle the heartbeat request and send 
// back the heartbeat response. If FORK is 1, the request is handled in a 
// separate process (guarantees reproducibility, i.e., memory state is always 
// the same). If FORK is 0, the request is handled in the main process.
//-----------------------------------------------------------------------------
int main(int argc, char *argv[]) {
  unsigned char* request;
  int csd, ssd;
  struct sockaddr_in addr = {AF_INET, htons(PORT), INADDR_ANY};
  int addrlen = sizeof(addr);
  
  // Simulate storing sensitive data from previous requests on the heap and then free it
  char* simData = simulateSensitiveData();
  printf("%lu bytes simulated sensitive data from previous requests stored on heap\n", strlen(simData));
  free(simData);

  // Create server socket, wait for connections and process the request
  ssd = createSocket(&addr);
  printf("Server socket created, waiting for connections\n\n");
  while((csd = accept(ssd, (struct sockaddr*)&addr, (unsigned*)&addrlen)) > 0) {
    printf("Client connected\n");
    if (FORK) {  // If FORK is 1, handle request in child process
      if (!fork()) {
        request = readRequest(csd);  // This is the child process, handle request
        if (request != NULL) {
          sendResponse(csd, request);
        }
        free(request);
        close(csd);
        exit(0);
      }
    } else {  // If FORK is 0, handle request in main process
      request = readRequest(csd);
      if (request != NULL) {
        sendResponse(csd, request);
      }
      free(request);
      close(csd);
    }
  }
}
    

//-----------------------------------------------------------------------------
// This function reads a packet that contains a heartbeat request from a client
// and returns a pointer to the received request (which contains payload 
// length, payload and padding). If more data is received than indicated by
// the packet header length, ignore the remaining data. If the request is
// malformed (invalid length in the packet header or fewer bytes than indicated
// by the packet header were received), return NULL.
//-----------------------------------------------------------------------------
unsigned char* readRequest(int csd) {
  
  // Receive packet header from client
  unsigned int requestLength = readPacketHeader(csd);                                              
  if (requestLength < (PAYLOAD_LENGTH_SIZE + MIN_PAYLOAD_PADDING_SIZE) || 
      requestLength > (PAYLOAD_LENGTH_SIZE + MAX_PAYLOAD_PADDING_SIZE)) {
    printf("Heartbeat request length %u not valid\n", requestLength);
    return NULL;
  }
  
  // Allocate memory for the request , receive length and message, and write 
  // them into the allocted memory.
  unsigned char* request = malloc(requestLength);
  unsigned char buf[BUF_SIZE];
  int allBytesReceived = 0;
  int pos = 0;
  int count = recv(csd, buf, BUF_SIZE, 0);
  while(count > 0 && !allBytesReceived) {
    if (pos + count > requestLength) {  // Makes sure that the allocated buffer 'request'
      count = requestLength - pos;      // is not overflowed, i.e., reads only as many bytes
    }                                   // as what fits into the buffer.
    memcpy(request+pos, buf, count);
    pos += count;
    if (pos == requestLength) {
      allBytesReceived = 1;
    } else {
      count = recv(csd, buf, BUF_SIZE, 0);
    }
  }
  if (!allBytesReceived) {
    printf("Heartbeat request contains fewer bytes than indicated in the packet header, this is not valid\n");
    return NULL;
  }
  printf("Heartbeat request received, length: %d (%d bytes packet header, %d bytes payload length, %d bytes payload/padding)\n", 
    PACKET_HEADER_SIZE + pos, PACKET_HEADER_SIZE, PAYLOAD_LENGTH_SIZE, requestLength - PAYLOAD_LENGTH_SIZE);
  return request;  
}


//-----------------------------------------------------------------------------
// This function sends a packet that contains a heartbeat response back to the 
// clent. The response is created based on parameter request, which contains 
// a pointer to the heartbeat request (payload length, payload and padding) 
// that was received from the client. The padding is not sent back to the 
// client.
//-----------------------------------------------------------------------------
void sendResponse(int csd, unsigned char* request) {
  
  // First two bytes of request is the payload length, store in payloadLength
  unsigned short payloadLength = 256 * request[0] + request[1];
  printf("Content of payload length field in heartbeat request: %d\n", payloadLength);
  
  // Create and send packet header
  sendPacketHeader(csd, PAYLOAD_LENGTH_SIZE + payloadLength);
  
  // Send payload length and payload
  send(csd, request, PAYLOAD_LENGTH_SIZE + payloadLength, 0);
  printf("Heartbeat response sent, length: %d (%d bytes packet header, %d bytes payload length, %d bytes payload)\n\n", 
    PACKET_HEADER_SIZE + PAYLOAD_LENGTH_SIZE + payloadLength, PACKET_HEADER_SIZE, PAYLOAD_LENGTH_SIZE, payloadLength);
}
    

//-----------------------------------------------------------------------------
// Creates a blocking socket and returns the socket descriptor.
//-----------------------------------------------------------------------------
int createSocket(struct sockaddr_in *addr) {
  int ssd=-1, z=1;
  if((ssd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    printf("%s", "Cannot setup socket\n");
    exit(-1);
  }
  setsockopt(ssd, SOL_SOCKET, SO_REUSEADDR, NULL, 0);
  if(bind(ssd, (struct sockaddr*)addr, sizeof(*addr)) < 0) {
    printf("%s", "Bind failed\n");
    close(ssd);
    exit(-1);
  }
  if(listen(ssd, 20) < 0) {
    printf("%s", "Listen failed\n");
    close(ssd);
    exit(-1);
  }
  return ssd;
}


//-----------------------------------------------------------------------------
// Simulates storage of sensitive data (from previous requests) on the heap.
//-----------------------------------------------------------------------------
char* simulateSensitiveData() {
  char* data = "GET /shop/home HTTP/1.1\nHost: www.shop.com\nUser-Agent: Mozilla/5.0\n\
Cookie: sessionid=71a120c543d894bec15f944bb20e0e7f\n\n\n\
POST /shop/login HTTP/1.1\nHost: www.shop.com\nUser-Agent: Mozilla/5.0\n\
Cookie: sessionid=71a120c543d894bec15f944bb20e0e7f\n\n\
user=alice&password=dHe*()H_J/2x\n\n\n\
GET /shop/specials HTTP/1.1\nHost: www.shop.com\nUser-Agent: Mozilla/5.0\n\
Cookie: sessionid=a8c8569929addc96773007f30d8c2c47\n\n\n\
POST /shop/pay HTTP/1.1\nHost: www.shop.ch\nUser-Agent: Mozilla/5.0\n\
Cookie: sessionid=a8c8569929addc96773007f30d8c2c47\n\n\
nameoncard=Alice Doe&ccnumber=1234 2345 3456 3456&cve=176&expires=07/29\n\n";   
  char* p = malloc(100000);
  strcpy(p, data);
  return p;
}
