package Protocol::ACME::Utils;

use strict;
use warnings;

sub pem2der
{
  my $pem = shift;
  $pem =~ s/^\-\-\-[^\n]*\n//mg;
  return decode_base64( $pem );
}

sub der2pem
{
  my $der = shift;
  my $tag = shift;

  my $pem = encode_base64( $der );
  $pem = "-----BEGIN $tag-----\n" . $pem . "-----END $tag-----\n";

  return $pem;
}

sub looks_like_pem
{
  my ($str) = @_;
  return (substr($str, 0, 1) eq '-') ? 1 : 0;
}

1;
