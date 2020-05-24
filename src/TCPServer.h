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
#ifndef INCLUDED_TCPSERVER
#define INCLUDED_TCPSERVER

#include <string>
#include <memory>

using ClientAddress = std::pair<std::string,int>; // address, port

class TCPServer;

class TCPTransaction
{
protected:
    int _debug = 0;
public:
  virtual void debug (int level) {_debug = level; };

  virtual void init (TCPServer&) = 0;
  virtual void send (const std::string&) = 0;
  virtual void recv (std::string&) = 0;

  virtual ClientAddress getClient() const = 0;

};

class TCPServer
{
protected:
  int _debug = 0;
  int _queue = 5;
public:
  virtual int socket() = 0;
  virtual ~TCPServer() = default;

  void queue(int q) { _queue = q; }

  virtual void debug (int level) {_debug = level; };

  virtual void bind (const std::string& host, const std::string& port, const std::string& family) = 0;
  virtual void listen () = 0;
  virtual std::unique_ptr<TCPTransaction> accept () = 0;
};

std::unique_ptr<TCPServer> create_server(bool is_tls_disabled);

#endif
