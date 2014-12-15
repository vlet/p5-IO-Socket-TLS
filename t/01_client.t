use strict;
use IO::Socket::TLS;
use Test::More;
pass;
done_testing;
exit;

# simple client
my $cl = IO::Socket::TLS->new('127.0.0.1:4443');
print $cl "GET / HTTP/1.0\r\n\r\n";
print <$cl>;

