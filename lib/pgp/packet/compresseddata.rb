require 'pgp/packet/packet'
require 'pgp/compressionalgorithm'


module PGP
module Packet


class CompressedData < Packet
  def initialize(algorithm)
    super(8)
    @algorithm = algorithm
  end

  attr_accessor :algorithm

  attr_accessor :body

  def scan(io)
    io.puts CompressionAlgorithm.dump_summary(@algorithm)
    io.puts "Data - #{@body.size} bytes"
  end

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    initpos = port.readlength
    algorithm = load_algorithm(port)
    packet = new(algorithm)
    if length.nil?
      data = port.read
    else
      data = port.read(length - (port.readlength - initpos))
    end
    packet.body = CompressionAlgorithm.decompress(algorithm, data)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_algorithm(port)
    load_1octet(port)
  end

  add_loader(8, method(:loader))
  add_scanner(8, method(:scanner))
end


end
end
