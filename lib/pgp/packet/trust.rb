require 'pgp/packet/packet'


module PGP
module Packet


class Trust < Packet
  def initialize(body = nil)
    super(12)
    @body = body
  end

  def scan(io)
    super
    "Body - #{@body.size} bytes"
  end

  attr_accessor :body

private

  def dump_body
    @body
  end

  def self.loader(port, length)
    body = port.read(length)
    new(body)
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(12, method(:loader))
  add_scanner(12, method(:scanner))
end


end
end
