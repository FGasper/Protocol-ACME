use strict;
use warnings;
use Protocol::ACME;
use Protocol::ACME::Challenge::Manual;
use Protocol::ACME::Challenge::SimpleSSH;
use Protocol::ACME::Challenge::LocalFile;

use HTTP::Tiny;
use IO::File;

use Convert::X509;

use Data::Dumper;

my $host = "api.letsencrypt.org.edgekey-staging.net";
#my $host = "acme-staging.api.letsencrypt.org";
#my $host = "acme-v01.api.letsencrypt.org";


my $account_key_file = shift;
my $cert_file        = shift;

if ( ! $account_key_file or ! $cert_file )
{
  die "Usage: perl foo.pl <account_key_file> <cert_file>";
}

eval
{
  # Creating an HTTP::Tiny is not strictly necessary but
  # this provides some flexibility and test coverage
  my $ua = HTTP::Tiny->new(
    verify_SSL => 0,
    default_headers => { Host => 'acme-staging.api.letsencrypt.org' },
  );

  my $acme = Protocol::ACME->new( host               => $host,
                                  account_key        => $account_key_file,
                                  account_key_format => "PEM",  # PEM is the default
                                  ua                 => $ua );


  $acme->directory();

  $acme->revoke( $cert_file );
};
if ( $@ )
{
  die $@ if ref $@ ne "Protocol::ACME::Exception";
  print "Error occured: Status: $@->{status}, Detail: $@->{detail}, Type: $@->{type}\n";
}
else
{
  print "Success\n";
}

