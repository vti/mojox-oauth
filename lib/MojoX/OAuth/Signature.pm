package MojoX::OAuth::Signature;

use strict;
use warnings;

use base 'Mojo::Base';
use overload '""' => sub { shift->to_string }, fallback => 1;

use Mojo::ByteStream 'b';
use MojoX::OAuth::Parameters;

__PACKAGE__->attr(method => 'POST');
__PACKAGE__->attr('url');
__PACKAGE__->attr([qw/consumer_secret token_secret/] => '');
__PACKAGE__->attr(params => sub { MojoX::OAuth::Parameters->new });

sub base_string {
    my $self = shift;

    my @values;

    # Add request method
    push @values, uc $self->method;

    # Add url
    my $url = $self->url;
    $url = "http://$url" unless $url =~ m{^https?://};
    push @values, b($url)->url_escape;

    # Add params
    push @values, b($self->params->to_string)->url_escape;

    return join '&' => @values;
}

sub signing_key {
    my $self = shift;

    return b($self->consumer_secret)->url_escape . '&'
      . b($self->token_secret)->url_escape;
}

sub to_string {
    my $self = shift;

    my $signature_method = $self->params->param('oauth_signature_method')
      || 'HMAC-SHA1';

    my $key = $self->signing_key;

    if ($signature_method eq 'PLAINTEXT') {
        return $key;
    }
    else {
        my $base_string = $self->base_string;

        # Calculating digest
        my $digest = '';
        if ($signature_method eq 'HMAC-SHA1') {
            $digest = b($base_string)->hmac_sha1_sum($key)->to_string;
        }
        else {
        }

        die 'Unsupported signature method: ' . $signature_method
          unless $digest;

        return b(pack('H*', $digest))->b64_encode('')->to_string;
    }
}

1;
