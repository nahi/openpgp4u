require 'pgp/mpi'
require 'pgp/packet/support'
require 'pgp/util'


module PGP
module Packet


module RSAKeySupport
  extend Support::ModuleSupport

  def initialize(algorithm = nil)
    unless [1, 2, 3].include?(algorithm)
      raise "Illegal algorithm"
    end
    super(algorithm)
    @n = nil
    @e = nil
    @d = nil
    @p = nil
    @q = nil
    @u = nil
  end

  attr_accessor :n, :e, :d, :p, :q, :u

  def scan(io)
    super
    io.puts "RSA Key (#{nbits} bits)"
    io.indent(4) do
      io.puts "n " << dump_component_bits(@n) if @n
      io.puts "e " << dump_component_bits(@e) if @e
      io.puts "d " << dump_component_bits(@d) if @d
      io.puts "p " << dump_component_bits(@p) if @p
      io.puts "q " << dump_component_bits(@q) if @q
      io.puts "u " << dump_component_bits(@u) if @u
    end
  end

  def nbits
    MPI.nbits(@n)
  end

  def as_primarykey_algorithm
    packet = as_primarykey_packet
    packet.extend(RSAKeySupport)
    packet.n = @n
    packet.e = @e
    packet.d = @d
    packet.p = @p
    packet.q = @q
    packet.u = @u
    packet
  end

  def key_material_secret_checksum
    body = MPI.encode(@d) + MPI.encode(@p) + MPI.encode(@q) + MPI.encode(@u)
    RSAKeySupport.calc_key_material_secret_checksum(body)
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
    MPI.encode(@n) + MPI.encode(@e)
  end

  def dump_key_material_secret
    MPI.encode(@d) + MPI.encode(@p) + MPI.encode(@q) + MPI.encode(@u) +
      dump_key_material_checksum
  end

  def dump_key_material_checksum
    dump_2octet(self.key_material_secret_checksum)
  end

  def self.calc_key_material_secret_checksum(body)
    [Util.checksum(body)].pack("n")
  end

  def self.load_key_material_public(packet, port)
    packet.extend(self)
    packet.n = MPI.load(port)
    packet.e = MPI.load(port)
  end

  def self.load_key_material_secret(packet, port)
    packet.extend(self)
    packet.d = MPI.load(port)
    packet.p = MPI.load(port)
    packet.q = MPI.load(port)
    packet.u = MPI.load(port)
  end

  def self.load_sessionkey(packet, data)
    packet.sessionkey = MPI.decode(data)
  end

  def self.included(mod)
    if mod.respond_to?(:add_key_material_factory_public)
      m = method(:load_key_material_public)
      mod.add_key_material_factory_public(1, m)
      mod.add_key_material_factory_public(2, m)
      mod.add_key_material_factory_public(3, m)
    end
    if mod.respond_to?(:add_key_material_factory_secret)
      m = method(:load_key_material_secret)
      mod.add_key_material_factory_secret(1, m)
      mod.add_key_material_factory_secret(2, m)
      mod.add_key_material_factory_secret(3, m)
    end
    if mod.respond_to?(:add_encryptedsessionkey_factory)
      m = method(:load_sessionkey)
      mod.add_encryptedsessionkey_factory(1, m)
      mod.add_encryptedsessionkey_factory(2, m)
      mod.add_encryptedsessionkey_factory(3, m)
    end
  end
end


end
end
