require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class Internal < Packet

  def initialize(type = nil)
    super(type)
  end

  attr_accessor :body

private

  def dump_body
    @body
  end

  def self.loader(port, length)
    packet = new()
    packet.body = port.read(length)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader((100..110).to_a, method(:loader))
  add_scanner((100..110).to_a, method(:scanner))
end


end
end
end
