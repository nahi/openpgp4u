require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class KeyExpirationTime < Packet
  def initialize(time = nil)
    super(9)
    self.time = time
  end

  attr_reader :time

  def time=(time)
    @time = Time.at(time.to_i)
  end

  def scan(io)
    super
    io.puts "Time - #{@time}"
  end

private

  def dump_body
    dump_time(@time)
  end

  def self.loader(port, length)
    new(load_time(port))
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  add_loader(9, method(:loader))
  add_scanner(9, method(:scanner))
end


end
end
end
