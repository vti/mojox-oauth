package MojoX::OAuth::Signature;

use strict;
use warnings;

use base 'Mojo::Base';
use overload '""' => sub { shift->to_string }, fallback => 1;

use Mojo::ByteStream 'b';
use Mojo::Parameters;

__PACKAGE__->attr(method => 'POST');
__PACKAGE__->attr('url');
__PACKAGE__->attr([qw/consumer_secret token_secret/] => '');
__PACKAGE__->attr(_params => sub { Mojo::Parameters->new });

sub sign {
    my $self = shift;
    my $params = shift;

    $self->params($params);

    $params->{oauth_signature} = $self->to_string;

    return $self;
}

sub params {
    my $self = shift;

    return $self->_params unless @_;

    if (ref $_[0] && ref $_[0] eq 'Mojo::Parameters') {
        $self->_params($_[0]);
    }
    else {
        my $params = ref $_[0] && ref $_[0] eq 'HASH' ? $_[0] : {@_};

        foreach my $key (keys %$params) {
            next if $key eq 'realm';

            $self->_params->append($key => $params->{$key});
        }
    }

    return $self;
}

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
    my $params = $self->params->to_hash;
    delete $params->{oauth_signature};
    delete $params->{realm};

    # Preparing pairs
    my @pairs;
    foreach my $key (keys %$params) {
        my $values = $params->{$key};
        $values = [$values] unless ref $values eq 'ARRAY';

        foreach my $v (@$values) {
            $key = b($key)->url_escape->to_string;
            $v   = b($v)->url_escape->to_string;
            push @pairs, [$key, $v];
        }
    }

    # Sorting pairs (first by name, then by value)
    @pairs = sort { $a->[0] cmp $b->[0] || $a->[1] cmp $b->[1] } @pairs;

    # Concatenating pairs
    my $pairs = join '&' => map { join '=' => @$_ } @pairs;

    push @values, b($pairs)->url_escape;

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
        warn "base_string=$base_string";

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
