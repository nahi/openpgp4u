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


class PrimaryUserID < Packet
  def initialize(primary = nil)
    super(25)
    self.primary = primary
  end

  def primary=(primary)
    @primary = !!primary
  end

  def scan(io)
    super
    io.puts "Primary User ID - #{@primary}"
  end

private

  def dump_body
    dump_1octet(@primary ? 1 : 0)
  end

  def self.loader(port, length)
    new(load_body(port).nonzero?)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_body(port)
    load_1octet(port)
  end

  add_loader(25, method(:loader))
  add_scanner(25, method(:scanner))
end


end
end
end
