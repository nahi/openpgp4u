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


class IssuerKeyID < Packet
  def initialize(keyid = nil)
    super(16)
    self.keyid = keyid
  end

  def scan(io)
    super
    io.puts "Key ID - 0x#{@keyid.unpack("H*")[0].upcase}"
  end

  def keyid=(keyid)
    unless keyid.length == 8
      raise "Illegal key ID"
    end
    @keyid = keyid
  end

private

  def dump_body
    @keyid
  end

  def self.loader(port, length)
    new(port.read(length))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(16, method(:loader))
  add_scanner(16, method(:scanner))
end


end
end
end
