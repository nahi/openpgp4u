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


require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class KeyServerPreferences < Packet
  NO_MODIFY = 0x80

  def initialize
    super(23)
    @no_modify = false
  end

  def no_modify=(no_modify)
    @no_modify = !!no_modify
  end

  def scan(io)
    super
    io.puts "No-modify" if @no_modify
  end

private

  def dump_body
    value = 0
    value |= NO_MODIFY if @no_modify
    dump_1octet(value)
  end

  def self.loader(port, length)
    octet1 = load_1octet(port)
    port.read(length - 1)
    packet = new()
    packet.no_modify = 1 if (octet1 & NO_MODIFY).nonzero?
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(23, method(:loader))
  add_scanner(23, method(:scanner))
end


end
end
end
