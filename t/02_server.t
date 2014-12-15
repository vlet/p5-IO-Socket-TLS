use strict;
use IO::Socket::TLS;
use Test::More;
pass;
done_testing;
exit;

# simple client
my $srv = IO::Socket::TLS->new(
    LocalAddr     => '0.0.0.0:4443',
    Listen        => 10,
    ReuseAddr     => 1,
    TLS_key_file  => 't/test.key',
    TLS_cert_file => 't/test.crt',
);
my $c    = $srv->accept;
my $line = <$c>;
print $line;
print $c "test\n";
