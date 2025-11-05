// ----------------------------------------------------------------------------
// Author:       M. Rennhard
// Date:         19.03.2021
// Description:  Common header file for heartbleed program
// ----------------------------------------------------------------------------

#define PORT 2222
#define PACKET_HEADER_SIZE 4
#define PAYLOAD_LENGTH_SIZE 2
#define MIN_PAYLOAD_PADDING_SIZE 1
#define MAX_PAYLOAD_PADDING_SIZE 65535
#define BUF_SIZE 1000
#define FORK 1

unsigned int readPacketHeader(int csd);
void sendPacketHeader(int csd, unsigned int packetContentLength);
