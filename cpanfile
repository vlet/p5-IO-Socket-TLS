requires 'perl', '5.008001';
requires 'IO::Socket::IP';
requires 'Protocol::TLS';
requires 'Scalar::Util';

on 'test' => sub {
    requires 'Test::More', '0.98';
};

