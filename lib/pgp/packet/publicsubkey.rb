require 'pgp/packet/key'
require 'pgp/packet/publickeysupport'


module PGP
module Packet


class PublicSubkey < Key
  include PublicKeySupport
  extend PublicKeySupport::ModuleSupport

  def initialize(algorithm = nil)
    super(14, algorithm)
  end

  def as_primarykey
    as_primarykey_algorithm
  end

  def as_primarykey_packet
    packet = PublicKey.new(@algorithm)
    packet.keycreated = @keycreated
    packet
  end

private

  def dump_body
    dump_publickey_body
  end

  def self.loader(port, length)
    packet = new()
    load_publickey_body(packet, port)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(14, method(:loader))
  add_scanner(14, method(:scanner))
end


end
end
