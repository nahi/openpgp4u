require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class Features < Packet
  MODIFICATION_DETECTION = 0x01

  def initialize(flags = nil)
    super(30)
    @modification_detection = false
    self.flags = flags
  end

  def scan(io)
    super
    io.puts "Modification Detection - #{@modification_detection}"
  end

  def flags=(flags)
    self.modification_detection = (flags & MODIFICATION_DETECTION).nonzero?
  end

  def modification_detection=(modification_detection)
    @modification_detection = !!modification_detection
  end

private

  def dump_body
    value = 0
    value |= MODIFICATION_DETECTION if @modification_detection
    dump_1octet(value) + "\000\000\000"
  end

  def self.loader(port, length)
    flags = load_1octet(port)
    port.read(length - 1)        # TBD: ignore
    new(flags)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(30, method(:loader))
  add_scanner(30, method(:scanner))
end


end
end
end
