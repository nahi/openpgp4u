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


class KeyFlags < Packet
  CERTIFY = 0x01
  SIGN = 0x02
  ENCRYPT_COMMUNICATION = 0x04
  ENCRYPT_STORAGE = 0x08
  SPLIT_KEY = 0x10
  AUTHENTICATION = 0x20
  GROUP_KEY = 0x80

  LABEL = {
    CERTIFY => "This key may be used to certify other keys",
    SIGN => "This key may be used to sign data",
    ENCRYPT_COMMUNICATION => "This key may be used to encrypt communications",
    ENCRYPT_STORAGE => "This key may be used to encrypt storage",
    SPLIT_KEY => "The private component of this key may have been split by a secret-sharing mechanism",
    AUTHENTICATION => "This key may be used for authentication",
    GROUP_KEY => "The private component of this key may be in the possession of more than one person",
  }

  def initialize(flags = nil)
    super(27)
    @certify = false
    @sign = false
    @encrypt_communication = false
    @encrypt_storage = false
    @split_key = false
    @authentication = false
    @group_key = false
    self.flags = flags
  end

  def flags=(flags)
    self.certify = (flags & CERTIFY).nonzero?
    self.sign = (flags & SIGN).nonzero?
    self.encrypt_communication = (flags & ENCRYPT_COMMUNICATION).nonzero?
    self.encrypt_storage = (flags & ENCRYPT_STORAGE).nonzero?
    self.split_key = (flags & SPLIT_KEY).nonzero?
    self.authentication = (flags & AUTHENTICATION).nonzero?
    self.group_key = (flags & GROUP_KEY).nonzero?
  end

  def certify=(certify)
    @certify = !!certify
  end

  def sign=(sign)
    @sign = !!sign
  end

  def encrypt_communication=(encrypt_communication)
    @encrypt_communication = !!encrypt_communication
  end

  def encrypt_storage=(encrypt_storage)
    @encrypt_storage = !!encrypt_storage
  end

  def split_key=(split_key)
    @split_key = !!split_key
  end

  def authentication=(authentication)
    @authentication = !!authentication
  end

  def group_key=(group_key)
    @group_key = !!group_key
  end

  def scan(io)
    super
    io.puts "#{LABEL[CERTIFY]}" if @certify
    io.puts "#{LABEL[SIGN]}" if @sign
    io.puts "#{LABEL[ENCRYPT_COMMUNICATION]}" if @encrypt_communication
    io.puts "#{LABEL[ENCRYPT_STORAGE]}" if @encrypt_storage
    io.puts "#{LABEL[SPLIT_KEY]}" if @split_key
    io.puts "#{LABEL[AUTHENTICATION]}" if @authentication
    io.puts "#{LABEL[GROUP_KEY]}" if @group_key
  end

private

  def dump_body
    value = 0
    value |= CERTIFY if @certify
    value |= SIGN if @sign
    value |= ENCRYPT_COMMUNICATION if @encrypt_communication
    value |= ENCRYPT_STORAGE if @encrypt_storage
    value |= SPLIT_KEY if @split_key
    value |= AUTHENTICATION if @authentication
    value |= GROUP_KEY if @group_key
    dump_1octet(value) + "\000\000\000"
  end

  def self.loader(port, length)
    flags = load_1octet(port)
    port.read(length - 1)
    new(flags)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(27, method(:loader))
  add_scanner(27, method(:scanner))
end


end
end
end
