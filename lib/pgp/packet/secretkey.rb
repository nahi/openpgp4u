require 'pgp/packet/key'
require 'pgp/packet/secretkeysupport'


module PGP
module Packet


class SecretKey < Key
  include SecretKeySupport
  extend SecretKeySupport::ModuleSupport

  def initialize(algorithm = nil)
    super(5, algorithm)
  end

private

  def dump_body
    dump_secretkey_body
  end

  def self.loader(port, length)
    packet = new()
    load_secretkey_body(packet, port, length)
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(5, method(:loader))
  add_scanner(5, method(:scanner))
end


end
end
