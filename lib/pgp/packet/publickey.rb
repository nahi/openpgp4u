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
require 'pgp/packet/publickeysupport'


module PGP
module Packet


class PublicKey < Key
  include PublicKeySupport
  extend PublicKeySupport::ModuleSupport

  def initialize(algorithm = nil)
    super(6, algorithm)
  end

private

  def dump_body
    dump_publickey_body
  end

  def self.loader(port, length)
    packet = new()
    load_publickey_body(packet, port)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(6, method(:loader))
  add_scanner(6, method(:scanner))
end


end
end
