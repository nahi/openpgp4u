require 'pgp/packet/sigsubpacket/packet'
require 'pgp/compressionalgorithm'


module PGP
module Packet
module SigSubPacket


class PreferredCompressionAlgorithm < Packet
  def initialize
    super(22)
    @algorithm = []
  end

  attr_reader :algorithm

  def scan(io)
    super
    @algorithm.each do |algo|
      io.puts "#{CompressionAlgorithm.label(algo)}(#{algo})"
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

  add_loader(22, method(:loader))
  add_scanner(22, method(:scanner))
end


end
end
end
