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


require 'pgp/mpi'
require 'pgp/packet/support'
require 'pgp/util'


module PGP
module Packet


module DSAKeySupport
  extend Support::ModuleSupport

  def initialize(algorithm = nil)
    if algorithm != 17
      raise "Illegal algorithm"
    end
    super(algorithm)
    @p = nil
    @q = nil
    @g = nil
    @y = nil
    @x = nil
  end

  attr_accessor :p, :q, :g, :y, :x
  
  def scan(io)
    super
    io.puts "DSA Key (#{nbits} bits)"
    io.indent(4) do
      io.puts "p " << dump_component_bits(@p) if @p
      io.puts "q " << dump_component_bits(@q) if @q
      io.puts "g " << dump_component_bits(@g) if @g
      io.puts "y " << dump_component_bits(@y) if @y
      io.puts "x " << dump_component_bits(@x) if @x
    end
  end

  def nbits
    MPI.nbits(@q)
  end

  def as_primarykey_algorithm
    packet = as_primarykey_packet
    packet.extend(DSAKeySupport)
    packet.p = @p
    packet.q = @q
    packet.g = @g
    packet.y = @y
    packet.x = @x
    packet
  end

  def key_material_secret_checksum
    body = MPI.encode(@x)
    DSAKeySupport.calc_key_material_secret_checksum(body)
  end

private

  def dump_component_bits(num)
    "(#{MPI.nbits(num)} bits)\n"
  end

  def public_encrypt(plain)
    PKeyAlgorithm.public_encrypt(self, plain)
  end

  def public_decrypt(cipher)
    PKeyAlgorithm.public_decrypt(self, cipher)
  end

  def secret_encrypt(plain)
    PKeyAlgorithm.secret_encrypt(self, plain)
  end

  def secret_decrypt(cipher)
    PKeyAlgorithm.secret_decrypt(self, cipher)
  end

  def dump_key_material_public
    raise "ToDo"
  end

  def dump_key_material_secret
    body = MPI.encode(@x) + dump_key_material_checksum
  end

  def dump_key_material_checksum
    raise "ToDo"
  end

  def self.calc_key_material_secret_checksum(body)
    Util.checksum(body)
  end

  def self.load_key_material_public(packet, port)
    packet.extend(self)
    packet.p = MPI.load(port)
    packet.q = MPI.load(port)
    packet.g = MPI.load(port)
    packet.y = MPI.load(port)
  end

  def self.load_key_material_secret(packet, port)
    packet.extend(self)
    packet.x = MPI.load(port)
    checksum = load_2octet(port)
    if checksum != packet.key_material_secret_checksum
      STDERR.puts "Illegal private key material checksum: #{checksum} / #{packet.key_material_secret_checksum}"
    end
  end

  def self.load_sessionkey(packet, data)
    packet.sessionkey = MPI.decode(data)
  end

  def self.included(mod)
    if mod.respond_to?(:add_key_material_factory_public)
      m = method(:load_key_material_public)
      mod.add_key_material_factory_public(17, m)
    end
    if mod.respond_to?(:add_key_material_factory_secret)
      m = method(:load_key_material_secret)
      mod.add_key_material_factory_secret(17, m)
    end
    if mod.respond_to?(:add_encryptedsessionkey_factory)
      m = method(:load_sessionkey)
      mod.add_encryptedsessionkey_factory(17, m)
    end
  end
end


end
end
