module PGP
module Packet


module S2KSupport
  attr_accessor :s2k_skey_algorithm
  attr_accessor :s2k_type
  attr_accessor :s2k_param
  attr_accessor :s2k_iv
  attr_accessor :s2k_data

  def scan(io)
    super
    if @s2k_type
      io.puts "S2K protected"
      io.indent(4) do
        io.puts "Type - #{S2KSpecifier.label(@s2k_type)}"
        io.puts "Algorithm - #{SKeyAlgorithm.label(@s2k_skey_algorithm)}"
        io.puts "IV - #{@s2k_iv.unpack("H*")[0]}"
      end
    end
  end

  module ModuleSupport
    def load_s2k(packet, port)
      s2kid = load_1octet(port)
      case s2kid
      when 0
        # nothing to load
      when 254, 255
        packet.s2k_skey_algorithm = load_1octet(port)
        packet.s2k_type, packet.s2k_param = S2KSpecifier.load_s2kparam(port)
        packet.s2k_iv =
          port.read(SKeyAlgorithm.blocksize(packet.s2k_skey_algorithm))
      else
        raise "Unknown s2k identifier: #{s2kid}"
      end
      return s2kid
    end

    def load_s2k_data(packet, port, length)
      packet.s2k_data = port.read(length)
    end
  end
end


end
end
