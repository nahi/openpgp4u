require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class IssuerKeyID < Packet
  def initialize(keyid = nil)
    super(16)
    self.keyid = keyid
  end

  def scan(io)
    super
    io.puts "Key ID - 0x#{@keyid.unpack("H*")[0].upcase}"
  end

  def keyid=(keyid)
    unless keyid.length == 8
      raise "Illegal key ID"
    end
    @keyid = keyid
  end

private

  def dump_body
    @keyid
  end

  def self.loader(port, length)
    new(port.read(length))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(16, method(:loader))
  add_scanner(16, method(:scanner))
end


end
end
end
