require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class PrimaryUserID < Packet
  def initialize(primary = nil)
    super(25)
    self.primary = primary
  end

  def primary=(primary)
    @primary = !!primary
  end

  def scan(io)
    super
    io.puts "Primary User ID - #{@primary}"
  end

private

  def dump_body
    dump_1octet(@primary ? 1 : 0)
  end

  def self.loader(port, length)
    new(load_body(port).nonzero?)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_body(port)
    load_1octet(port)
  end

  add_loader(25, method(:loader))
  add_scanner(25, method(:scanner))
end


end
end
end
