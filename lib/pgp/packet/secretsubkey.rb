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


require 'pgp/packet/key'
require 'pgp/packet/secretkeysupport'


module PGP
module Packet


class SecretSubkey < Key
  include SecretKeySupport
  extend SecretKeySupport::ModuleSupport

  def initialize(algorithm = nil)
    super(7, algorithm)
  end

  def as_primarykey
    as_primarykey_algorithm
  end

  def as_primarykey_packet
    packet = SecretKey.new(@algorithm)
    packet.keycreated = @keycreated
    packet
  end

private

  def dump_body
    dump_secretkey_body
  end

  def self.loader(port, length)
    packet = new()
    load_secretkey_body(packet, port, length)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(7, method(:loader))
  add_scanner(7, method(:scanner))
end


end
end
