require 'pgp/packet/userattrsubpacket/packet'


module PGP
module Packet
module UserAttrSubPacket


class Image < Packet
  def initialize(body = nil)
    super(1)
    @version = 1
    @format = 1
    @body = body
  end

  attr_accessor :version
  attr_accessor :format
  attr_accessor :body

  def scan(io)
    super
    io.puts "Version - #{@version}"
    io.puts "Format - #{@format}"
  end

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    initpos = port.readlength
    packet = new()
    load_image_header(packet, port)
    packet.body = port.read(length - (port.readlength - initpos))
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_image_header(packet, port)
    length = load_image_length(port)
    packet.version = load_version(port)
    case packet.version
    when 1
      load_image_version_1(packet, port)
    else
      raise "Not supported: #{packet.version}"
    end
  end

  def self.load_image_version_1(packet, port)
    packet.format = load_1octet(port)
    header_rest = port.read(12)
    if header_rest != "\000" * 12
      raise "Illegal image header (version 1): #{header_rest}"
    end
  end

  # Note that unlike other multi-octet numerical values in this document, due
  # to an historical accident this value is encoded as a little-endian number.
  def self.load_image_length(port)
    octet1 = load_1octet(port)
    octet2 = load_1octet(port)
    octet2 << 8 + octet1
  end

  def self.load_version(port)
    load_1octet(port)
  end

  add_loader(1, method(:loader))
  add_scanner(1, method(:scanner))
end


end
end
end
