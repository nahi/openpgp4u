require 'pgp/packet/packet'


module PGP
module Packet


class Key < Packet
  def nbits
    raise NotImplementedError
  end

  def encrypt
    raise NotImplementedError
  end

  def decrypt
    raise NotImplementedError
  end
end


end
end
