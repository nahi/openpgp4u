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


class Marker < Packet
  PGPMarker = "PGP"

  def initialize
    super(10)
  end

  def scan(io)
    super
    io.puts PGPMarker.inspect
  end

private

  def dump_body
    PGPMarker
  end

  def self.loader(port, length)
    marker = port.read(length)
    if marker != PGPMarker
      raise "Illegal marker: #{marker}"
    end
    new
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(10, method(:loader))
  add_scanner(10, method(:scanner))
end


end
end
