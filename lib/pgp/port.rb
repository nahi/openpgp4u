module PGP


class Port
  def self.for(port)
    new(port)
  end

  class << self
    private :new
  end

  def initialize(port)
    @port = port
    @readlength = 0
    @str = ''
  end

  def readlength
    @readlength
  end

  def read(size = nil)
    if size.nil?
      return @str + @port.read
    end
    if @str.empty?
      result = @port.read(size)
    elsif @str.size < size
      result = @str
      result << @port.read(size - @str.size)
      @str = ''
    else
      result = @str[0, size]
      @str = @str[size..-1]
    end
    @readlength += result.size
    if result.size != size
      raise "Input stream corruption: #{result.size}/#{size}"
    end
    result
  end

  def put(str)
    @str << str
    @readlength -= str.size
  end

  def eof?
    @port.eof?
  end
end


end
