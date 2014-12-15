package IO::Socket::TLS;
use 5.008001;
use strict;
use warnings;

use IO::Socket::IP;
our @ISA = qw(IO::Socket::IP);
use Protocol::TLS::Client;
use Protocol::TLS::Server;
use Time::HiRes qw(time);
use Errno qw( EINVAL EINPROGRESS EISCONN );

our $VERSION = "0.01";

my %levels = (
    debug     => 0,
    info      => 1,
    notice    => 2,
    warning   => 3,
    error     => 4,
    critical  => 5,
    alert     => 6,
    emergency => 7,
);

my $DEBUG =
  exists $ENV{TLS_DEBUG} && exists $levels{ $ENV{TLS_DEBUG} }
  ? $levels{ $ENV{TLS_DEBUG} }
  : $levels{error};

my $start_time = 0;

sub DEBUG {
    my ( $level, $message ) = @_;
    return if $DEBUG < $level;

    chomp($message);
    my $now = time;
    if ( $now - $start_time < 60 ) {
        $message =~ s/\n/\n           /g;
        printf "[%05.3f] %s\n", $now - $start_time, $message;
    }
    else {
        my @t = ( localtime() )[ 5, 4, 3, 2, 1, 0 ];
        $t[0] += 1900;
        $t[1]++;
        $message =~ s/\n/\n                      /g;
        printf "[%4d-%02d-%02d %02d:%02d:%02d] %s\n", @t, $message;
        $start_time = $now;
    }
}

sub configure {
    my ( $self, $args ) = @_;
    $self->configure_tls($args);
    $self->SUPER::configure($args)
      or return $self->error("@ISA configuration failed");

    return $self;
}

sub configure_tls {
    my ( $self, $args ) = @_;

    ${*$self}->{_args} = $args;
    ${*$self}->{_r}    = '';
    ${*$self}->{_w}    = '';

    my $is_server =
      grep { exists $args->{$_} } (qw(TLS_server SSL_server Listen));

    my %default = ();

    ( $default{cert_file} ) =
      map { $args->{$_} } grep { exists $args->{$_} }
      (qw(TLS_cert_file SSL_cert_file));

    ( $default{key_file} ) =
      map { $args->{$_} } grep { exists $args->{$_} }
      (qw(TLS_key_file SSL_key_file));

    ${*$self}->{_tls} =
      $is_server
      ? Protocol::TLS::Server->new(%default)
      : Protocol::TLS::Client->new();

    $self;
}

sub connect {
    my $self = shift;
    my $s    = ${*$self};

    return $self if ${*$self}->{_TLS_opened};    # already connected

    if ( !${*$self}->{_TLS_opening} ) {

        # call SUPER::connect if the underlying socket is not connected
        # if this fails this might not be an error (e.g. if $! = EINPROGRESS
        # and socket is nonblocking this is normal), so keep any error
        # handling to the client
        DEBUG( 2, 'socket not yet connected' );
        $self->SUPER::connect(@_) || return;
        DEBUG( 2, 'socket connected' );

        # IO::Socket works around systems, which return EISCONN or similar
        # on non-blocking re-connect by returning true, even if $! is set
        # but it does not clear $!, so do it here
        $! = undef;
    }
    return $self->connect_TLS;
}

sub connect_TLS {
    my $self = shift;
    my $s    = ${*$self};

    my $con;
    if ( !${*$self}->{_TLS_opening} ) {
        my $args = ${*$self}->{_args};
        my ($host) =
          grep { exists $args->{$_} ? $args->{$_} : '' }
          (qw(TLS_verifycn_name SSL_verifycn_name PeerHost PeerAddr));

        $con = ${*$self}->{_con} = ${*$self}->{_tls}->new_connection(
            $host,
            on_handshake_finish => sub {
                ${*$self}->{_tls_ctx}     = shift;
                ${*$self}->{_TLS_opening} = 0;
                ${*$self}->{_TLS_opened}  = 1;
            },
            on_data => sub {
                ${*$self}->{_read_buffer} .= $_[1];
            }
        );
    }

    $con = ${*$self}->{_con};

    while ( !${*$self}->{_TLS_opened} ) {
        while ( my $record = $con->next_record ) {
            ${*$self}->{_w} .= $record;
        }

        my $l = length( ${*$self}->{_w} );
        my $written = syswrite $self, ${*$self}->{_w}, $l, 0;
        return unless defined $written;
        DEBUG( 0, "write $written" );
        substr ${*$self}->{_w}, 0, $written, '';

        my $readen = sysread $self, ${*$self}->{_r}, 8192,
          length( ${*$self}->{_r} );
        return unless defined $readen;
        DEBUG( 0, "read $readen" );
        $con->feed( ${*$self}->{_r} );
        ${*$self}->{_r} = '';
    }

    tie *{$self}, "IO::Socket::TLS::TLS_HANDLE", $self;

    $self;
}

sub accept {
    my $self  = shift || return;
    my $class = shift || 'IO::Socket::TLS';

    my $socket = ${*$self}{'_TLS_opening'};
    if ( !$socket ) {

        # underlying socket not done
        DEBUG( 2, 'no socket yet' );
        $socket = $self->SUPER::accept($class) || return;
        DEBUG( 2, 'accept created normal socket ' . $socket );
    }

    $self->accept_TLS($socket) || return;
    DEBUG( 2, 'accept_TLS ok' );

    return wantarray ? ( $socket, getpeername($socket) ) : $socket;
}

sub accept_TLS {
    my $self = shift;
    my $socket =
      ( @_ && UNIVERSAL::isa( $_[0], 'IO::Handle' ) ) ? shift : $self;

    my $con;
    if ( !${*$socket}{'_TLS_opening'} ) {

        $con = ${*$socket}->{_con} = ${*$self}->{_tls}->new_connection(
            on_handshake_finish => sub {
                ${*$socket}->{_tls_ctx}     = shift;
                ${*$socket}->{_TLS_opening} = 0;
                ${*$socket}->{_TLS_opened}  = 1;
                ${*$socket}->{_read_buffer} = '';
            },
            on_data => sub {
                ${*$socket}->{_read_buffer} .= $_[1];
            }
        );
    }
    $con = ${*$socket}->{_con};

    while ( !${*$socket}->{_TLS_opened} ) {
        my $readen = sysread $socket, ${*$socket}->{_r}, 8192,
          length( ${*$socket}->{_r} );
        return unless defined $readen;
        DEBUG( 0, "read $readen" );
        $con->feed( ${*$socket}->{_r} );
        ${*$socket}->{_r} = '';

        while ( my $record = $con->next_record ) {
            ${*$socket}->{_w} .= $record;
        }

        my $l = length( ${*$socket}->{_w} );
        my $written = syswrite $socket, ${*$socket}->{_w}, $l, 0;
        return unless defined $written;
        DEBUG( 0, "write $written" );
        substr ${*$socket}->{_w}, 0, $written, '';
    }

    tie *{$socket}, "IO::Socket::TLS::TLS_HANDLE", $socket;

    $socket;
}

sub generic_read {
    my ( $self, $func, undef, $length, $offset ) = @_;
    my $s      = ${*$self};
    my $con    = ${*$self}->{_con};
    my $buffer = \$_[2];
    DEBUG( 0, uc($func) . " offset: $offset, length: $length" );

    my $len;
    do {
        untie *{$self};
        my $l = sysread $self, ${*$self}->{_r}, $length || 8192,
          length( ${*$self}->{_r} );
        tie *{$self}, "IO::Socket::TLS::TLS_HANDLE", $self;

        DEBUG( 0, uc($func) . " readed " . ( defined $l ? $l : "[undef]" ) );
        return $l unless $l;

        $con->feed( ${*$self}->{_r} );
        ${*$self}->{_r} = '';

        $len = length( ${*$self}->{_read_buffer} );
    } while ( !$len );

    substr( $$buffer, $offset || 0,
        length($$buffer), ${*$self}->{_read_buffer} );
    ${*$self}->{_read_buffer} = '';
    DEBUG( 0, uc($func) . " return $len" );

    return $len;
}

sub read {
    my $self = shift;
    return $self->generic_read( 'read', @_ );
}

sub sysread {
    my $self = shift;
    return $self->generic_read( 'sysread', @_ );
}

sub generic_write {
    my ( $self, $func, undef, $length, $offset ) = @_;

    my $con = ${*$self}->{_con};
    my $ctx = ${*$self}->{_tls_ctx};
    $length = $length ? $length : length $_[2];
    $offset ||= 0;

    DEBUG( 0, uc($func) . " length: " . $length );
    $ctx->send( $_[2] );

    while ( my $record = $con->next_record ) {
        ${*$self}->{_w} .= $record;
    }

    my $l = length( ${*$self}->{_w} );
    DEBUG( 0, uc($func) . " to write: " . $l );

    # ugly hack
    untie *{$self};
    my $written = syswrite $self, ${*$self}->{_w}, $l, 0;
    tie *{$self}, "IO::Socket::TLS::TLS_HANDLE", $self;

    DEBUG( 0,
        uc($func) . " written " . ( defined $written ? $written : "[undef]" ) );
    return undef unless defined $written;

    substr ${*$self}->{_w}, 0, $l, '';
    DEBUG( 0, uc($func) . " return $length" );

    return $length;
}

sub write {
    my $self = shift;
    return $self->generic_write( 'write', @_ );
}

sub syswrite {
    my $self = shift;
    return $self->generic_write( 'syswrite', @_ );
}

sub print {
    my $self = shift;
    my $string = join( ( $, or '' ), @_, ( $\ or '' ) );
    return $self->write($string);
}

sub printf {
    my ( $self, $format ) = ( shift, shift );
    return $self->write( sprintf( $format, @_ ) );
}

sub getc {
    my ( $self, $buffer ) = ( shift, undef );
    return $buffer if $self->read( $buffer, 1, 0 );
}

sub readline {
    my $self = shift;

    if ( not defined $/ or wantarray ) {

        # read all and split

        my $buf = '';
        while (1) {
            my $rv = $self->sysread( $buf, 2**16, length($buf) );
            if ( !defined $rv ) {
                next if $!{EINTR};
                return;
            }
            elsif ( !$rv ) {
                last;
            }
        }

        if ( !defined $/ ) {
            return $buf;
        }
        elsif ( ref($/) ) {
            my $size = ${$/};
            die "bad value in ref \$/: $size" unless $size > 0;
            return $buf =~ m{\G(.{1,$size})}g;
        }
        elsif ( $/ eq '' ) {
            return $buf =~ m{\G(.*\n\n+|.+)}g;
        }
        else {
            return $buf =~ m{\G(.*$/|.+)}g;
        }
    }

    # read only one line
    if ( ref($/) ) {
        my $size = ${$/};

        # read record of $size bytes
        die "bad value in ref \$/: $size" unless $size > 0;
        my $buf = '';
        while ( $size > length($buf) ) {
            my $rv = $self->sysread( $buf, $size - length($buf), length($buf) );
            if ( !defined $rv ) {
                next if $!{EINTR};
                return;
            }
            elsif ( !$rv ) {
                last;
            }
        }
        return $buf;
    }

    my ( $delim0, $delim1 ) = $/ eq '' ? ( "\n\n", "\n" ) : ( $/, '' );

    die "empty \$/ is not supported" if $delim1 ne '';
    my $buf = '';
    while (1) {
        my $rv = $self->sysread( $buf, 1, length($buf) );
        if ( !defined $rv ) {
            next if $!{EINTR};
            return;
        }
        elsif ( !$rv ) {
            last;
        }
        index( $buf, $delim0 ) >= 0 and last;
    }
    return $buf;
}

sub close {
    my $self = shift;
    my $s    = ${*$self};
    my $con  = ${*$self}->{_con};
    $con->shutdown(1);
    $self->write('');
    $self->SUPER::close;
}

package IO::Socket::TLS::TLS_HANDLE;
use strict;
use Errno 'EBADF';
use Scalar::Util qw(weaken);

sub TIEHANDLE {
    my ( $class, $handle ) = @_;
    weaken($handle);
    bless \$handle, $class;
}

sub READ     { ${ shift() }->sysread(@_) }
sub READLINE { ${ shift() }->readline(@_) }
sub GETC     { ${ shift() }->getc(@_) }

sub PRINT  { ${ shift() }->print(@_) }
sub PRINTF { ${ shift() }->printf(@_) }
sub WRITE  { ${ shift() }->syswrite(@_) }

sub FILENO { ${ shift() }->fileno(@_) }

sub TELL { $! = EBADF; return -1 }

sub BINMODE {
    return 0;
}    # not perfect, but better than not implementing the method

sub CLOSE {    #<---- Do not change this function!
    my $tls = ${ $_[0] };
    local @_;
    $tls->close();
}

1;
__END__

=encoding utf-8

=head1 NAME

IO::Socket::TLS - is a drop-in replacement for IO::Socket::SSL

=head1 SYNOPSIS

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

=head1 DESCRIPTION

IO::Socket::TLS is a module with API compatible with L<IO::Socket::SSL>.
IO::Socket::TLS internaly uses L<Protocol::TLS>.

=head1 STATUS

Current status - experimental

=head1 LICENSE

Copyright (C) Vladimir Lettiev.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Vladimir Lettiev E<lt>thecrux@gmail.comE<gt>

=cut

