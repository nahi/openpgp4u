module PGP
module Packet


module Support
  def dump_1octet(data)
    [data].pack("C")
  end

  def dump_2octet(data)
    [data].pack("n")
  end

  def dump_4octet(data)
    [data].pack("N")
  end

  def dump_version
    dump_1octet(@version)
  end

  def dump_time(time)
    dump_4octet(time.to_i)
  end

  def dump_length_old(len)
    case length_type_old(len)
    when 0
      dump_1octet(len)
    when 1
      dump_2octet(len)
    when 2
      dump_4octet(len)
    else
      raise "Not supported"
    end
  end

  def dump_length_new(len)
    if len <= 191
      dump_1octet(len)
    elsif len <= 8383
      len -= 192
      dump_1octet(len / 256 + 192) + dump_1octet(len % 256)
    elsif len <= 0xFFFFFFFF
      dump_1octet(255) + dump_4octet(len)
    else
      raise "Not supported"
    end
  end

  def length_type_old(len)
    if len <= 0xff
      0
    elsif len <= 0xffff
      1
    elsif len <= 0xffffffff
      2
    else
      raise "Not supported"
    end
  end

  module ModuleSupport
    def load_1octet(port)
      port.read(1).unpack("C")[0]
    end

    def load_2octet(port)
      port.read(2).unpack("n")[0]
    end

    def load_4octet(port)
      port.read(4).unpack("N")[0]
    end

    def load_keyid(port)
      port.read(8)
    end

    def load_time(port)
      Time.at(load_4octet(port))
    end

    def load_length_old(port, type)
      case type
      when 0
        load_1octet(port)
      when 1
        load_2octet(port)
      when 2
        load_4octet(port)
      else
        nil
      end
    end

    def load_length_new(port)
      octet1 = load_1octet(port)
      if octet1 <= 191
        octet1
      elsif octet1 <= 223
        octet2 = load_1octet(port)
        ((octet1 - 192) << 8) + octet2 + 192
      elsif octet1 == 255
        load_4octet(port)
      else
        raise "Unknown format"
      end
    end
  end
end


end
end
