# Copyright 2004  NAKAMURA, Hiroshi <nakahiro@sarion.co.jp>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'pgp/packet/packet'
require 'pgp/pkeyalgorithm'


module PGP
module Packet


class PublicKeyEncryptedSessionKey < Packet
  def initialize(version = 3)
    super(1)
    @version = version
    @keyid = nil
    @algorithm = nil
    @sessionkey = nil
  end

  attr_accessor :version

  attr_reader :keyid, :algorithm

  def keyid=(keyid)
    @keyid = keyid
  end

  def algorithm=(algorithm)
    @algorithm = algorithm
  end

  attr_accessor :sessionkey

  def scan(io)
    super
    io.puts "Version - #{@version}"
    io.puts "Key ID - 0x#{@keyid.unpack("H*")[0].upcase}"
    io.puts "Algorithm: #{PKeyAlgorithm.label(@algorithm)}(#{@algorithm})"
    io.puts PKeyAlgorithm.dump_sessionkey(@algorithm, sessionkey)
  end

private

  def dump_body
    dump_version + dump_publickey
  end

  def dump_version
    dump_1octet(@version)
  end

  def dump_publickey
    dump_keyid + dump_1octet(@algorithm)
  end

  def dump_keyid
    raise "ToDo"
  end

  def dump_encrypted
    raise NotImplementedError
  end

  def self.loader(port, length)
    initpos = port.readlength
    version = load_version(port)
    packet = new(version)
    packet.keyid = load_keyid(port)
    packet.algorithm = load_algorithm(port)

    data = port.read(length - (port.readlength - initpos))
    unless SESSIONKEY_FACTORY.key?(packet.algorithm)
      raise "Not supported: #{packet.algorithm}"
    end
    SESSIONKEY_FACTORY[packet.algorithm].call(packet, data)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_version(port)
    load_1octet(port)
  end

  def self.load_algorithm(port)
    load_1octet(port)
  end

  SESSIONKEY_FACTORY = {}

  def self.add_encryptedsessionkey_factory(algorithm, method)
    SESSIONKEY_FACTORY[algorithm] = method
  end

  add_loader(1, method(:loader))
  add_scanner(1, method(:scanner))
end


end
end
