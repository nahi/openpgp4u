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


module PGP
module Packet


class Partial < Packet
  def initialize
    super(-1)
    @body = nil
  end

  attr_accessor :body

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    packet = new()
    packet.body = port.read(length)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end
end


end
end
