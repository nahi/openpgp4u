require 'pgp/packet/key'
require 'pgp/packet/publickeysupport'


module PGP
module Packet


class PublicKey < Key
  include PublicKeySupport
  extend PublicKeySupport::ModuleSupport

  def initialize(algorithm = nil)
    super(6, algorithm)
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

  add_loader(6, method(:loader))
  add_scanner(6, method(:scanner))
end


end
end
