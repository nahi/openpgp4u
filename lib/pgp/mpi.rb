require 'stringio'


module PGP


module MPI
  def dump(num, port = nil)
    bytes = [nbits(num)].pack("n") + to_bytes(num).sub(/^\000+/, '')
    if port
      port << bytes
    else
      bytes
    end
  end
  module_function :dump

  def load(port)
    length = port.read(2).unpack("n")[0]
    bytes = (length + 7) / 8
    body = port.read(bytes)
    if bytes != body.length
      raise "Illegal format: expecting #{bytes} bytes as a body"
    end
    from_bytes(body)
  end
  module_function :load

  def encode(num)
    dump(num)
  end
  module_function :encode

  def decode(string)
    load(StringIO.new(string.to_s))
  end
  module_function :decode

  def nbits(num)
    idx = num.size * 8 - 1
    while idx >= 0
      if num[idx].nonzero?
        return idx + 1
      end
      idx -= 1
    end
    0
  end
  module_function :nbits

  def to_bytes(num)
    bits = num.size * 8
    pos = value = 0
    str = ""
    for idx in 0..(bits - 1)
      if num[idx].nonzero?
        value |= (num[idx] << pos)
      end
      pos += 1
      if pos == 32
        str = [value].pack("N") + str
        pos = value = 0
      end
    end
    str
  end
  module_function :to_bytes

  def from_bytes(bytes)
    num = 0
    bytes.each_byte do |c|
      num <<= 8
      num |= c
    end
    num
  end
  module_function :from_bytes
end


end


if __FILE__ == $0
  p PGP::MPI.encode(511)
  p PGP::MPI.decode(PGP::MPI.encode(511))
  p PGP::MPI.encode(65537)
  p PGP::MPI.decode(PGP::MPI.encode(65537))
end
