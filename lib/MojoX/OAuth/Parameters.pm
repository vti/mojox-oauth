package MojoX::OAuth::Parameters;

use strict;
use warnings;

use base 'Mojo::Base';
use overload '""' => sub { shift->to_string }, fallback => 1;

use Mojo::ByteStream 'b';

sub params {
    my $self = shift;
    my $hash = shift;

    $self->{params} ||= {};

    return $self->{params} unless $hash;

    foreach my $key (keys %$hash) {
        my $value = $hash->{$key};

        if (exists $self->params->{$key}) {
            unless (ref $self->params->{$key} eq 'ARRAY') {
                $self->params->{$key} = [$self->params->{$key}];
            }

            push @{$self->params->{$key}},
              ref $value eq 'ARRAY' ? @$value : $value;
        }
        else {
            $self->params->{$key} = $hash->{$key};
        }
    }

    return $self;
}

sub param {
    my $self = shift;

    return $self->params->{$_[0]} if @_ == 1;

    $self->params->{$_[0]} = $_[1];

    return $self;
}

sub to_hash {
    my $self = shift;

    my $hash = {};
    foreach my $key (keys %{$self->params}) {
        $hash->{$key} = $self->param($key);
    }

    return $hash;
}

sub to_string {
    my $self = shift;

    # Copy
    my %params = %{$self->params};

    # Cleanup params
    delete $params{realm};
    delete $params{oauth_signature};

    # Preparing pairs
    my @pairs;
    foreach my $key (keys %params) {
        my $values = $params{$key};
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
    return join '&' => map { join '=' => @$_ } @pairs;
}

1;
