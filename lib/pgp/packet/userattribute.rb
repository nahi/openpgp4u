require 'pgp/packet/packet'


module PGP
module Packet


class UserAttribute < Packet
  def initialize
    super(17)
    @subpacket = []
  end

  attr_reader :subpacket

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    packet = new()
    packet.replace(load_subpacket(port, length))
    packet
  end

  def self.scanner(io, port, length)
    io.puts "Sub:"
    io.indent(4) do
      scan_subpacket(io, port, length)
    end
  end

  def self.load_subpacket(port, length)
    subpackets = []
    initpos = port.readlength
    while (port.readlength - initpos) < length
      subpackets << UserAttrSubPacket::Packet.load(port)
    end
    if (port.readlength - initpos) != length
      raise "Illegal subpacket format"
    end
    subpackets
  end

  def self.scan_subpacket(io, port, length)
    initpos = port.readlength
    while (port.readlength - initpos) < length
      UserAttrSubPacket::Packet.scan(port, io)
    end
    if (port.readlength - initpos) != length
      raise "Illegal subpacket format"
    end
  end

  add_loader(17, method(:loader))
  add_scanner(17, method(:scanner))
end


end
end
