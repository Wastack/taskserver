////////////////////////////////////////////////////////////////////////////////
//
// Copyright 2006 - 2018, Paul Beckingham, Federico Hernandez.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// http://www.opensource.org/licenses/mit-license.php
//
////////////////////////////////////////////////////////////////////////////////

#include <iostream>

#include <sys/socket.h>
#include <sys/errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <format.h>

#include "SimpleClient.h"

constexpr int MAX_BUF = 16384;

SimpleClient::~SimpleClient()
{
  if (_socket)
  {
    shutdown (_socket, SHUT_RDWR);
    close (_socket);
  }
}

void SimpleClient::connect (const std::string& host, const std::string& port)
{
  _host = host;
  _port = port;

  int ret;


  // use IPv4 or IPv6, does not matter.
  struct addrinfo hints {};
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_PASSIVE; // use my IP

  struct addrinfo* res;
  ret = ::getaddrinfo (host.c_str (), port.c_str (), &hints, &res);
  if (ret != 0)
    throw std::string (::gai_strerror (ret));

  // Try them all, stop on success.
  struct addrinfo* p;
  for (p = res; p != NULL; p = p->ai_next)
  {
    if ((_socket = ::socket (p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
      continue;

    // When a socket is closed, it remains unavailable for a while (netstat -an).
    // Setting SO_REUSEADDR allows this program to assume control of a closed,
    // but unavailable socket.
    int on = 1;
    if (::setsockopt (_socket,
                      SOL_SOCKET,
                      SO_REUSEADDR,
                      (const void*) &on,
                      sizeof (on)) == -1)
      throw std::string (::strerror (errno));

    if (::connect (_socket, p->ai_addr, p->ai_addrlen) == -1)
      continue;

    break;
  }

  free (res);

  if (p == NULL)
    throw format ("Could not connect to {1} {2}", host, port);
}

void SimpleClient::send( const std::string& data)
{
  std::string packet = "XXXX" + data;

  // Encode the length.
  unsigned long l = packet.length ();
  packet[0] = l >>24;
  packet[1] = l >>16;
  packet[2] = l >>8;
  packet[3] = l;

  unsigned int total = 0;
  unsigned int remaining = packet.length ();

  while (total < packet.length ())
  {
    int status;
    do
    {
      status = ::send (_socket, packet.c_str () + total, remaining, 0); // All
    }
    while (errno == EINTR || errno == EAGAIN);

    if (status == -1)
      break;

    total     += (unsigned int) status;
    remaining -= (unsigned int) status;
  }

  if(_debug > 0)
  {
    std::cout << "c: INFO Sending 'XXXX"
              << data.c_str ()
              << "' (" << total << " bytes)"
              << std::endl;
  }
}

void SimpleClient::recv (std::string& data)
{
  data = "";          // No appending of data.
  int received = 0;

  // Get the encoded length.
  unsigned char header[4] {};
  do
  {
    received = ::recv(_socket, header, 4, 0);
  }
  while (received > 0 &&
         (errno == EINTR ||
          errno == EAGAIN));

  int total = received;

  // Decode the length.
  unsigned long expected = (header[0]<<24) |
                           (header[1]<<16) |
                           (header[2]<<8) |
                            header[3];
  if (_debug > 0)
    std::cout << "c: INFO expecting " << expected << " bytes.\n";

  // Arbitrary buffer size.
  char buffer[MAX_BUF];

  // Keep reading until no more data.  Concatenate chunks of data if a) the
  // read was interrupted by a signal, and b) if there is more data than
  // fits in the buffer.
  do
  {
    do
    {
      received = ::recv (_socket, buffer, MAX_BUF - 1, 0);
    }
    while (received > 0 &&
           (errno == EINTR ||
            errno == EAGAIN));

    // Other end closed the connection.
    if (received == 0)
    {
      if (_debug > 0)
        std::cout << "c: INFO Peer has closed the TLS connection\n";
      break;
    }

    // Something happened.
    if (_debug > 0 && received < 0)
    {
      std::cout << "c: WARNING " << ::strerror(errno) << '\n';
    }
    else if (received < 0)
      throw std::string (::strerror(errno)); // TODO better exception?

    buffer [received] = '\0';
    data += buffer;
    total += received;

    // TODO limit?
  }
  while (received > 0 && total < (int) expected);

  if (_debug > 0)
    std::cout << "c: INFO Receiving 'XXXX"
              << data.c_str ()
              << "' (" << total << " bytes)"
              << std::endl;
}
