package MojoX::Client::OAuth;

use strict;
use warnings;

use base 'Mojo::Base';

use Mojo::Client;
use Mojo::ByteStream 'b';
use MojoX::OAuth::Signature;

__PACKAGE__->attr(client => sub { Mojo::Client->singleton });

sub request_token { shift->_make_request('POST' => @_) }
sub access_token  { shift->_make_request('POST' => @_) }

sub async {
    my $clone = shift->new;
    $clone->{async} = 1;
    return $clone;
}

sub _make_request {
    my $self = shift;
    my $method = shift;
    my $url = shift;
    my $settings = shift;

    my $cb; $cb = pop @_ if ref $_[-1] && ref $_[-1] eq 'CODE';

    my $client = $self->{async} ? $self->client->async : $self->client;

    my $tx = $client->build_tx($method => $url => @_);

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

    return $self->client->process($tx => $cb);
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
