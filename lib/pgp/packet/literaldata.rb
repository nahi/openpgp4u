require 'pgp/packet/packet'


module PGP
module Packet


class LiteralData < Packet
  FORMATS = {
    0x62 => "Binary",
    0x74 => "Text",
    0x75 => "Text(UTF-8)",
  }

  def self.format_include?(format)
    FORMATS.key?(format)
  end

  def self.format_label(format)
    FORMATS[format]
  end

  def initialize
    super(11)
    @format = @filename = @mtime = @body = nil
  end

  attr_reader :format
  attr_accessor :filename
  attr_accessor :mtime
  attr_accessor :body

  def format=(format)
    @format = format
  end

  def scan(io)
    io.puts "Format - #{format_label}"
    io.puts "File name - #{@filename}"
    io.puts "The modification date or the creation time of the packet - #{@mtime}"
    io.puts "Body - #{@body.size} bytes"
  end

  def format_label
    LiteralData.format_label(@format)
  end

private

  def dump_body
    raise "ToDo"
  end

  def self.loader(port, length)
    initpos = port.readlength
    packet = new()
    packet.format = load_format(port)
    packet.filename = load_filename(port)
    packet.mtime = load_time(port)
    packet.body = port.read(length - (port.readlength - initpos))
    packet
  end

  def self.scanner(io, port, length)
    loader(port, length).scan(io)
  end

  def self.load_format(port)
    load_1octet(port)
  end

  def self.load_filename(port)
    size = load_1octet(port)
    port.read(size)
  end

  add_loader(11, method(:loader))
  add_scanner(11, method(:scanner))
end


end
end
