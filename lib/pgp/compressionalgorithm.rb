module PGP


module CompressionAlgorithm
  ALGORITHMS = {
    0 => "Uncompressed",
    1 => "ZIP (RFC1951)",
    2 => "ZLIB (RFC1950)",
    3 => "BZip2",
    100 => "Private/Experimental algorithm",
    101 => "Private/Experimental algorithm",
    102 => "Private/Experimental algorithm",
    103 => "Private/Experimental algorithm",
    104 => "Private/Experimental algorithm",
    105 => "Private/Experimental algorithm",
    106 => "Private/Experimental algorithm",
    107 => "Private/Experimental algorithm",
    108 => "Private/Experimental algorithm",
    109 => "Private/Experimental algorithm",
    110 => "Private/Experimental algorithm",
  }

  def self.include?(algorithm)
    ALGORITHMS.key?(algorithm)
  end

  def self.label(algorithm)
    ALGORITHMS[algorithm]
  end

  def self.dump_summary(algorithm)
    "Compression algorithm - #{label(algorithm)}(#{algorithm})"
  end

  def self.compress(algorithm, data)
    case algorithm
    when 0
      data
    when 1
      raise "ToDo"
    else
      raise "Not supported"
    end
  end

  def self.decompress(algorithm, data)
    case algorithm
    when 0
      data
    when 1
      require 'zlib'
      z = Zlib::Inflate.new(-15)
      z.inflate(data) + z.finish
    else
      raise "Not supported"
    end
  end
end


end
