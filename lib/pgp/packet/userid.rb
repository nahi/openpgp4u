require 'pgp/packet/packet'


module PGP
module Packet


class UserID < Packet
  def initialize(userid = nil)
    super(13)
    self.userid = userid
  end

  def scan(io)
    super
    io.puts "User ID: #{@userid}"
  end

  attr_accessor :userid

private

  def dump_body
    @userid
  end

  def self.loader(port, length)
    new(port.read(length))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(13, method(:loader))
  add_scanner(13, method(:scanner))
end


end
end
