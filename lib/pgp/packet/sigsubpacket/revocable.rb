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
require 'pgp/skeyalgorithm'


module PGP
module Packet
module SigSubPacket


class Revocable < Packet
  def initialize(revocable = nil)
    super(7)
    self.revocable = revocable
  end

  def revocable
    @revocable
  end

  def revocable=(revocable)
    unless [0, 1].include?(revocable)
      raise "Illegal value: #{revocable}"
    end
    @revocable = revocable
  end

  def scan(io)
    super
    io.puts "Revocable - #{@revocable.zero? ? false : true}"
  end

private

  def dump_body
    dump_1octet(@revocable)
  end

  def self.loader(port, length)
    new(load_revocable(port))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_revocable(port)
    load_1octet(port)
  end

  add_loader(7, method(:loader))
  add_scanner(7, method(:scanner))
end


end
end
end
