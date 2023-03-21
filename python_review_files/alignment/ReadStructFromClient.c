
#include <stdio.h>      /* for printf() and fprintf() */
#include <sys/socket.h> /* for recv() and send() */
#include <unistd.h>     /* for close() */
#include <arpa/inet.h>

#define RCVBUFSIZE 1024  /* Size of receive buffer */

void ReadStructFromClient(int clntSocket)
{

  // Read three integers of different sizes, from the client.

  short int si;
  int i;
  long long int lli;

  /*****************************************/

  // Read a struct object from the client.

  struct {
    short int si;
    int i;
    long long int lli;
  } rx_data;

  recv(clntSocket, &rx_data, sizeof(rx_data), 0);

  printf("Short int: %hd\n", rx_data.si);
  printf("int: %d\n", rx_data.i);
  printf("Long long int: %lli\n", rx_data.lli);

  close(clntSocket);    /* Close client socket */
}

