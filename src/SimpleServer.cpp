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

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "SimpleServer.h"
#include <iostream>
#include <string.h>
#include <unistd.h>

void SimpleTransaction::init(TCPServer& server)
{
  struct sockaddr_in sa_cli {};
  socklen_t client_len = sizeof sa_cli;
  do
  {
    _socket = accept (server.socket(), (struct sockaddr *) &sa_cli, &client_len);
  }
  while (errno == EINTR);

  if (_socket < 0)
    throw std::string (::strerror (errno));

  // Obtain client info.
  char topbuf[512];
  _address = inet_ntop (AF_INET, &sa_cli.sin_addr, topbuf, sizeof (topbuf));
  _port    = ntohs (sa_cli.sin_port);
  if (_debug)
    std::cout << "s: INFO connection from "
              << _address
              << " port "
              << _port
              << '\n';
}

void SimpleTransaction::send(const std::string& message)
{
  std::string packet = "XXXX" + message;

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
      status = ::send (_socket, packet.c_str () + total, remaining, 0);
    }
    while (errno == EINTR ||
           errno == EAGAIN);

    if (status == -1)
      break;

    total     += (unsigned int) status;
    remaining -= (unsigned int) status;
  }

  if (_debug)
    std::cout << "s: INFO Sending 'XXXX"
              << message.c_str ()
              << "' (" << total << " bytes)"
              << std::endl;
}

void SimpleTransaction::recv(std::string& in_data)
{
  in_data = "";          // No appending of data.
  int received = 0;

  // Get the encoded length.
  unsigned char header[4] {};
  do
  {
    received = ::recv (_socket, header, 4, 0); // All
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
  if (_debug)
    std::cout << "s: INFO expecting " << expected << " bytes.\n";


  // Arbitrary buffer size.
  constexpr int MAX_BUF = 16384;
  char buffer[MAX_BUF];

  // Keep reading until no more data.  Concatenate chunks of data if a) the
  // read was interrupted by a signal, and b) if there is more data than
  // fits in the buffer.
  do
  {
    do
    {
      received = ::recv (_socket, buffer, MAX_BUF - 1, 0); // All
    }
    while (received > 0 &&
           (errno == EINTR ||
            errno == EAGAIN));

    // Other end closed the connection.
    if (received == 0)
    {
      if (_debug)
        std::cout << "s: INFO Peer has closed the TLS connection\n";
      break;
    }

    // Something happened.
    if (received < 0 && _debug > 0)
    {
      std::cout << "c: WARNING " << strerror (errno) << '\n';
    }
    else if (received < 0)
      throw std::string (strerror (errno));

    buffer [received] = '\0';
    in_data += buffer;
    total += received;
  }
  while (received > 0 && total < (int) expected);

  if (_debug)
    std::cout << "s: INFO Receiving 'XXXX"
              << in_data.c_str ()
              << "' (" << total << " bytes)"
              << std::endl;
}

ClientAddress SimpleTransaction::getClient() const
{
    return std::make_pair(_address, _port);
}

SimpleServer::~SimpleServer()
{
  if (_socket)
  {
    shutdown (_socket, SHUT_RDWR);
    close (_socket);
  }
}


void SimpleServer::bind (const std::string& host, const std::string& port, const std::string& family)
{
  // use IPv4 or IPv6, does not matter.
  struct addrinfo hints {};
  hints.ai_family   = (family == "IPv6" ? AF_INET6 :
                       family == "IPv4" ? AF_INET  :
                                          AF_UNSPEC);
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags    = AI_PASSIVE; // use my IP

  struct addrinfo* res;
  int ret = ::getaddrinfo (host.c_str (), port.c_str (), &hints, &res);
  if (ret != 0)
    throw std::string (::gai_strerror (ret));

  for (struct addrinfo* p = res; p != NULL; p = p->ai_next)
  {
    // IPv4
    void *addr;
    int ipver;
    if (p->ai_family == AF_INET)
    {
      struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
      addr = &(ipv4->sin_addr);
      ipver = 4;
    }
    // IPv6
    else
    {
      struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
      addr = &(ipv6->sin6_addr);
      ipver = 6;
    }

    // Convert the IP to a string and print it:
    char ipstr[INET6_ADDRSTRLEN];
    inet_ntop (p->ai_family, addr, ipstr, sizeof ipstr);
    if (_debug)
      std::cout << "s: INFO IPv" << ipver << ": " << ipstr << '\n';
  }

  if ((_socket = ::socket (res->ai_family,
                           res->ai_socktype,
                           res->ai_protocol)) == -1)
    throw std::string ("Can not bind to  ") + host + port;

  // When a socket is closed, it remains unavailable for a while (netstat -an).
  // Setting SO_REUSEADDR allows this program to assume control of a closed, but
  // unavailable socket.
  int on = 1;
  if (::setsockopt (_socket,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    (const void*) &on,
                    sizeof (on)) == -1)
    throw std::string (::strerror (errno));

  // Also listen to IPv4 with IPv6 in dual-stack situations
  if (res->ai_family == AF_INET6)
  {
    int off = 0;
    if (::setsockopt (_socket,
                      IPPROTO_IPV6,
                      IPV6_V6ONLY,
                      (const void*) &off,
                      sizeof (off)) == -1)
      if (_debug)
        std::cout << "s: Unable to use IPv6 dual stack\n";
  }

  if (::bind (_socket, res->ai_addr, res->ai_addrlen) == -1)
  {
    // TODO This is research to determine whether this is the right location to
    //      inject a helpful log message, such as
    //
    //      "Check to see if the server is already running."
    std::cout << "### bind failed\n";
    throw std::string (::strerror (errno));
  }
}

void SimpleServer::listen()
{
  if (::listen (_socket, _queue) < 0)
    throw std::string (::strerror (errno));

  if (_debug)
    std::cout << "s: INFO Server listening.\n";
}

std::unique_ptr<TCPTransaction> SimpleServer::accept()
{
  auto tx = std::make_unique<SimpleTransaction>();
  if (_debug)
    tx->debug (_debug);

  tx->init (*this);
  return tx;
}




