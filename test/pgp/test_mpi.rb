require 'test/unit'
require 'pgp/mpi'


module TestPGP


class TestMPI < Test::Unit::TestCase
  def test_511
    assert_equal("\000\t\001\377", PGP::MPI.encode(511))
    assert_equal(511, PGP::MPI.decode(PGP::MPI.encode(511)))
  end

  def test_65537
    assert_equal("\000\021\001\000\001", PGP::MPI.encode(65537))
    assert_equal(65537, PGP::MPI.decode(PGP::MPI.encode(65537)))
  end
end


end
