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


class KeyExpirationTime < Packet
  def initialize(time = nil)
    super(9)
    self.time = time
  end

  attr_reader :time

  def time=(time)
    @time = Time.at(time.to_i)
  end

  def scan(io)
    super
    io.puts "Time - #{@time}"
  end

private

  def dump_body
    dump_time(@time)
  end

  def self.loader(port, length)
    new(load_time(port))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(9, method(:loader))
  add_scanner(9, method(:scanner))
end


end
end
end
