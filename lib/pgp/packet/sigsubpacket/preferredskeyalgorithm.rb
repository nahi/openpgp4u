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


class PreferredSkeyAlgorithm < Packet
  def initialize
    super(11)
    @algorithm = []
  end

  attr_reader :algorithm

  def scan(io)
    super
    @algorithm.each do |algo|
      io.puts "#{SKeyAlgorithm.label(algo)}(#{algo})"
    end
  end

private

  def dump_body
    @algorithm.sort.collect { |algo|
      dump_1octet(algo)
    }.join
  end

  def self.loader(port, length)
    packet = new()
    length.times do
      packet.algorithm << load_algorithm(port)
    end
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_algorithm(port)
    load_1octet(port)
  end

  add_loader(11, method(:loader))
  add_scanner(11, method(:scanner))
end


end
end
end
