# NAME

IO::Socket::TLS - is a drop-in replacement for IO::Socket::SSL

# SYNOPSIS

    use IO::Socket::TLS;

    # Client
    my $cl = IO::Socket::TLS->new('google.com:443');
    print $cl "GET / HTTP/1.0\r\n\r\n";
    print <$cl>;

    # Server
    my $srv = IO::Socket::TLS->new(
        LocalAddr     => '0.0.0.0:4443',
        Listen        => 10,
        ReuseAddr     => 1,
        TLS_key_file  => 'test.key',
        TLS_cert_file => 'test.crt',
    );
    my $con = $srv->accept;
    my $line = <$con>;
    print $line;
    print $con "test\n";

# DESCRIPTION

IO::Socket::TLS is a module with API compatible with [IO::Socket::SSL](https://metacpan.org/pod/IO::Socket::SSL).
IO::Socket::TLS internaly uses [Protocol::TLS](https://metacpan.org/pod/Protocol::TLS).

# STATUS

Current status - experimental

# LICENSE

Copyright (C) Vladimir Lettiev.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

# AUTHOR

Vladimir Lettiev <thecrux@gmail.com>
