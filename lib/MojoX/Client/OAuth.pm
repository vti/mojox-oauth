package MojoX::Client::OAuth;

use strict;
use warnings;

use base 'Mojo::Client';

use Mojo::ByteStream 'b';
use MojoX::OAuth::Signature;

sub request_token {
    my $self = shift;
    return $self->_tx_queue_or_process($self->build_tx('POST', @_));
}

sub access_token {
    my $self = shift;
    return $self->_tx_queue_or_process($self->build_tx('POST', @_));
}

sub build_tx {
    my $self = shift;

    # OAuth settings
    my $settings = $_[2];

    # Parent object
    my ($tx, $cb) = $self->SUPER::build_tx(@_[0, 1, 3 .. $#_]);

    # Request
    my $req = $tx->req;

    my $params = $settings->{params};

    $params->{oauth_signature_method} ||= 'HMAC-SHA1';
    $params->{oauth_nonce}            ||= _nonce();
    $params->{oauth_timestamp}        ||= time;
    $params->{oauth_version}          ||= '1.0';
    $params->{realm}                  ||= 'Mojo (Perl)';

    # Initialize signature object
    my $signature = MojoX::OAuth::Signature->new(
        url             => $req->url->to_string,
        method          => $req->method,
        consumer_secret => $settings->{consumer_secret},
        token_secret    => $settings->{token_secret}
    );
    $signature->params->params($params);

    $params->{oauth_signature} = $signature->to_string;

    $req->headers->header(Authorization => 'OAuth ' . join ',' =>
        map { $_ . '="' . b($params->{$_})->url_escape . '"' }
        sort keys %$params);

    warn $req;

    return $tx unless wantarray;
    return $tx, $cb;
}

sub _nonce {
    my @s = (0 .. 9, 'a' .. 'z', 'A' .. 'Z');

    my $nonce = '';

    for (1 .. (rand(27) + 8)) {
        $nonce .= $s[rand($#s)];
    }

    return $nonce;
}

1;
