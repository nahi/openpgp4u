module PGP


module S2KSpecifier
  TYPES = {
    0 => ["Simple S2K"],
    1 => ["Salted S2K"],
    2 => ["Illegal value"],
    3 => ["Iterated and Salted S2K"],
    100 => ["Private/Experimental S2K"],
    101 => ["Private/Experimental S2K"],
    102 => ["Private/Experimental S2K"],
    103 => ["Private/Experimental S2K"],
    104 => ["Private/Experimental S2K"],
    105 => ["Private/Experimental S2K"],
    106 => ["Private/Experimental S2K"],
    107 => ["Private/Experimental S2K"],
    108 => ["Private/Experimental S2K"],
    109 => ["Private/Experimental S2K"],
    110 => ["Private/Experimental S2K"],
  }

  def self.include?(type)
    TYPES.key?(type)
  end

  def self.label(type)
    if data = TYPES[type]
      data[0]
    else
      raise "Not supported: #{type}"
    end
  end

  def self.dump_summary(type)
    "S2K Specifier - #{label(type)}(#{type})"
  end

  def self.load_s2kparam(port)
    type = port.read(1).unpack("C*")[0]
    hash_algorithm = port.read(1).unpack("C*")[0]
    hash_len = HashAlgorithm.hashlength(hash_algorithm)
    case type
    when 0x00
      return type, nil
    when 0x01
      salt = port.read(8)
      return type, salt
    when 0x03
      salt = port.read(8)
      count = port.read(1)
      return type, salt, count
    else
      raise "Unknown type: #{type}"
    end
  end
end


end
