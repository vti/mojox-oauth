package MojoX::OAuth::Server;

use strict;
use warnings;

use base 'Mojo::Base';

use Mojo::ByteStream 'b';
use Mojo::Parameters;
use MojoX::OAuth::Signature;
use MojoX::OAuth::Util;

__PACKAGE__->attr([qw/method url/]);
__PACKAGE__->attr([qw/consumer_secret token_secret/]);
__PACKAGE__->attr(params => sub { Mojo::Parameters->new });

sub process {
    my $self = shift;
    my $req = shift;

    my $header = $req->headers->header('Authorization');
    return unless $header && $header =~ s/^OAuth //;

    $self->params->append(map { ($_ =~ m/^(.*?)="([^\"]+)"/) }
          split ',' => b($header)->url_unescape);

    #use Data::Dumper;
    #warn Dumper $self->params;

    return unless $self->param('oauth_consumer_key');
    return unless $self->param('oauth_nonce');
    return unless $self->param('oauth_timestamp');

    $self->method($req->method);
    $self->url($req->url->to_abs->to_string);

    return $self;
}

sub consumer_key { shift->param('oauth_consumer_key') }
sub token        { shift->param('oauth_token') }
sub verifier     { shift->param('oauth_verifier') }
sub callback_url { shift->param('oauth_callback') }

sub param { shift->params->param(@_) }

sub check_signature {
    my $self = shift;

    my $signature = MojoX::OAuth::Signature->new(
        url             => $self->url,
        method          => $self->method,
        consumer_secret => $self->consumer_secret,
        token_secret    => $self->token_secret
    );
    $signature->params($self->params);

    warn "signature=$signature";

    return "$signature" eq $self->param('oauth_signature') ? 1 : 0;
}

sub generate_token        { MojoX::OAuth::Util->generate_hex_string(8,  32) }
sub generate_token_secret { MojoX::OAuth::Util->generate_hex_string(32, 64) }
sub generate_verifier     { MojoX::OAuth::Util->generate_hex_string(8,  32) }

1;
