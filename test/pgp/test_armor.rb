require 'test/unit'
require 'pgp/armor'


module TestPGP


class TestArmor < Test::Unit::TestCase
  def test_armor
    src = <<EOP
-----BEGIN PGP MESSAGE-----

yDgBO22WxBHv7O8X7O/jygAEzol56iUKiXmV+XmpCtmpqQUKiQrFqclFqUDBovzS
vBSFjNSiVHsuAA==
=njUN
-----END PGP MESSAGE-----
EOP

    d = PGP::Armor.new(src)
    assert_equal(src, d.dump)
  end
end


end
