require 'pgp/packet/sigsubpacket/packet'
require 'pgp/hashalgorithm'


module PGP
module Packet
module SigSubPacket


class PreferredHashAlgorithm < Packet
  def initialize
    super(21)
    @algorithm = []
  end

  attr_reader :algorithm

  def scan(io)
    super
    @algorithm.each do |algo|
      io.puts HashAlgorithm.label(algo)
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

  add_loader(21, method(:loader))
  add_scanner(21, method(:scanner))
end


end
end
end
