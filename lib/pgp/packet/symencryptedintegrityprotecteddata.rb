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


class SymEncryptedIntegrityProtectedData < Packet
  def initialize(version = 1)
    super(18)
    @version = version
    @cipher = nil
  end

  attr_accessor :version
  attr_accessor :cipher
  attr_accessor :plain

  def scan(io)
    super
    io.puts "Version - #{@version}"
    io.puts "Encrypted data + MDC SHA1(20 bytes)"
  end

  def decrypt(algo, key)
    block = SKeyAlgorithm.decrypt(algo, key, @cipher, :normal_cfb)
    header = block[0, 10]
    body = block[10, block.size - 10 - 22]
    mdcheader = block[-22, 2]
    mdcbody = block[-20..-1]
    require 'digest/sha1'
    if Digest::SHA1.digest(header + body + mdcheader) != mdcbody
      raise "MDC check failed"
    end
    @plain = body
  end

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    initpos = port.readlength
    version = load_version(port)
    packet = new(version)
    packet.cipher = port.read(length - (port.readlength - initpos))
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_version(port)
    load_1octet(port)
  end

  add_loader(18, method(:loader))
  add_scanner(18, method(:scanner))
end


end
end
