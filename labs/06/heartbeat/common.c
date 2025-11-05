//-----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         18.03.2021
// Description:  Common code for heartbeat program
//-----------------------------------------------------------------------------

#include <string.h>
#include <netdb.h>
#include "common.h"


//-----------------------------------------------------------------------------
// This function reads a 4 byte long packet header from a socket and returns
// the 4 bytes as an unsigned int.
//-----------------------------------------------------------------------------
unsigned int readPacketHeader(int csd) {
  unsigned char packetHeader[PACKET_HEADER_SIZE];
  unsigned char buf[BUF_SIZE];
  int packetHeaderReceived = 0;
  int pos = 0;
  int count = recv(csd, buf, PACKET_HEADER_SIZE-pos, 0);
  while(count > 0 && !packetHeaderReceived) {
    memcpy(packetHeader+pos, buf, count);
    pos += count;
    if (pos == PACKET_HEADER_SIZE) {
      packetHeaderReceived = 1;
    } else {
      count = recv(csd, buf, PACKET_HEADER_SIZE-pos, 0);
    }
  }
  unsigned int packetContentLength = 256 * 256 * 256 * packetHeader[0] + 
                                     256 * 256 * packetHeader[1] + 
                                     256 * packetHeader[2] +
                                     packetHeader[3];
  return packetContentLength;
}


//-----------------------------------------------------------------------------
// This function gets an unsigned int as a parameter, converts it to an array
// of 4 bytes and writes this array as a packet header to a socket.
//-----------------------------------------------------------------------------
void sendPacketHeader(int csd, unsigned int packetContentLength) {
  unsigned char packetContentLengthBytes[4];
  packetContentLengthBytes[0] = (packetContentLength >> 24) & 0xFF;
  packetContentLengthBytes[1] = (packetContentLength >> 16) & 0xFF;
  packetContentLengthBytes[2] = (packetContentLength >> 8) & 0xFF;
  packetContentLengthBytes[3] = packetContentLength & 0xFF;
  send(csd, packetContentLengthBytes, 4, 0);
}
