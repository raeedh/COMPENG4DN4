
The following is a short description of each version of the Echo
client/server code.

1. EchoClientServer.py

   Basic client/server where the client executes a single recv to
   check for echoed text.

2. EchoClientServerClientBind.py

   Same as 1 except that the client is always bound to the same socket
   address (and port 40000).

3. EchoClientServerIPv6.py

   Same as 1 except that IPv6 socket addresses are used. This will
   only work locally unless there is IPv6 connectivity between
   machines.

4. EchoClientServerOneRecv.py

   Same as 1. Used to experiment with client recv buffer size.

5. EchoClientServerMultiRecvB.py

   Adds multiple recvs so that everything works regardless of the recv
   buffer size. It prints the output each time the client does a
   recv. This one is broken when non-ascii characters are sent.

6. EchoClientServerMultiRecvF.py

   Same as 5 except that the non-ascii problem is fixed.


