require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class KeyServerPreferences < Packet
  NO_MODIFY = 0x80

  def initialize
    super(23)
    @no_modify = false
  end

  def no_modify=(no_modify)
    @no_modify = !!no_modify
  end

  def scan(io)
    super
    io.puts "No-modify" if @no_modify
  end

private

  def dump_body
    value = 0
    value |= NO_MODIFY if @no_modify
    dump_1octet(value)
  end

  def self.loader(port, length)
    octet1 = load_1octet(port)
    port.read(length - 1)
    packet = new()
    packet.no_modify = 1 if (octet1 & NO_MODIFY).nonzero?
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(23, method(:loader))
  add_scanner(23, method(:scanner))
end


end
end
end
