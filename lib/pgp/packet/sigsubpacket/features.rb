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


class Features < Packet
  MODIFICATION_DETECTION = 0x01

  def initialize(flags = nil)
    super(30)
    @modification_detection = false
    self.flags = flags
  end

  def scan(io)
    super
    io.puts "Modification Detection - #{@modification_detection}"
  end

  def flags=(flags)
    self.modification_detection = (flags & MODIFICATION_DETECTION).nonzero?
  end

  def modification_detection=(modification_detection)
    @modification_detection = !!modification_detection
  end

private

  def dump_body
    value = 0
    value |= MODIFICATION_DETECTION if @modification_detection
    dump_1octet(value) + "\000\000\000"
  end

  def self.loader(port, length)
    flags = load_1octet(port)
    port.read(length - 1)        # TBD: ignore
    new(flags)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(30, method(:loader))
  add_scanner(30, method(:scanner))
end


end
end
end
