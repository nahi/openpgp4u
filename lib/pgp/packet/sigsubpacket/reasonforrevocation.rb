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


class ReasonForRevocation < Packet
  CODE = {
    0x00 => "No reason specified (key revocations or cert revocations)",
    0x01 => "Key is superceded (key revocations)",
    0x02 => "Key material has been compromised (key revocations)",
    0x03 => "Key is retired and no longer used (key revocations)",
    0x20 => "User id information is no longer valid (cert revocations)",
  }

  def initialize(revocationcode = nil)
    super(29)
    self.revocationcode = revocationcode
    @reasonstring = nil
  end

  attr_reader :revocationcode

  def revocationcode=(revocationcode)
    unless CODE.key?(revocationcode)
      raise "Unknown revocation code: #{revocationcode}"
    end
    @revocationcode = revocationcode
  end

  attr_accessor :reasonstring

  def scan(io)
    super
    io.puts "Revocation Code - #{CODE[@revocationcode]}(#{@revocationcode})"
    io.puts "Reason String - #{@reasonstring}"
  end

private

  def dump_body
    dump_1octet(@revocationcode) + @reasonstring
  end

  def self.loader(port, length)
    code = load_1octet(port)
    packet = new(code)
    packet.reasonstring = port.read(length - 1)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(29, method(:loader))
  add_scanner(29, method(:scanner))
end


end
end
end
