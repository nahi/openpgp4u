require 'pgp/packet/packet'


module PGP
module Packet


class Marker < Packet
  PGPMarker = "PGP"

  def initialize
    super(10)
  end

  def scan(io)
    super
    io.puts PGPMarker.inspect
  end

private

  def dump_body
    PGPMarker
  end

  def self.loader(port, length)
    marker = port.read(length)
    if marker != PGPMarker
      raise "Illegal marker: #{marker}"
    end
    new
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(10, method(:loader))
  add_scanner(10, method(:scanner))
end


end
end
