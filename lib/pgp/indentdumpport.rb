module PGP


class IndentDumpPort
  def self.for(port)
    new(port)
  end

  class << self
    private :new
  end

  def initialize(port)
    @port = port
    @indent = 0
  end

  def puts(str)
    @port.print(" " * @indent)
    @port.puts(str)
  end

  def indent(size, &block)
    begin
      record = @indent
      @indent += size
      yield
    ensure
      @indent = record
    end
  end
end


end
