require 'pgp/packet/sigsubpacket/packet'


module PGP
module Packet
module SigSubPacket


class CreationTime < Packet
  def initialize(time = nil)
    super(2)
    self.time = time
  end

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

  add_loader(2, method(:loader))
  add_scanner(2, method(:scanner))
end


end
end
end
