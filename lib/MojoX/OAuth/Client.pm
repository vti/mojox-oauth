package MojoX::OAuth::Client;

use strict;
use warnings;

use base 'Mojo::Base';

use Mojo::ByteStream 'b';
use Mojo::Client;
use Mojo::URL;
use MojoX::OAuth::Signature;
use MojoX::OAuth::Util;

__PACKAGE__->attr(client => sub { Mojo::Client->singleton });

__PACKAGE__->attr([qw/consumer_key consumer_secret callback_url/]);
__PACKAGE__->attr(
    [qw/request_token_url access_token_url user_authorization_url/]);
__PACKAGE__->attr(signature_method => 'HMAC-SHA1');
__PACKAGE__->attr(realm            => 'MojoX::OAuth (Perl)');

__PACKAGE__->attr([qw/token token_secret/]);

__PACKAGE__->attr('success');

sub request_token {
    my $self = shift;

    return $self->_make_request('request_token' => $self->request_token_url =>
          {callback_url => $self->callback_url} => @_);
}

sub access_token {
    my $self = shift;

    $self->_make_request('access_token' => $self->access_token_url => @_);
}

sub request_resource { shift->_make_request('request_resource' => @_) }

sub clone {
    my $self = shift;

    my $clone = $self->new;

    # Copy attributes
    foreach my $attr (
        qw/
        consumer_key consumer_secret callback_url
        request_token_url access_token_url user_authorization_url
        signature_method
        realm
        /
      )
    {
        $clone->$attr($self->$attr);
    }

    return $clone;
}

sub tx  { shift->client->tx }
sub res { shift->tx->success }

sub _make_request {
    my $self = shift;
    my $type = shift;
    my $url  = shift;
    my $args = shift;

    my $cb;
    $cb = pop @_ if ref $_[-1] && ref $_[-1] eq 'CODE';

    my $client = $cb ? $self->client->async : $self->client;

    my $tx = $client->build_tx('POST' => $url => @_);

    my $req = $tx->req;

    my $params = {};
    $params->{oauth_consumer_key}     ||= $self->consumer_key;
    $params->{oauth_signature_method} ||= $self->signature_method;
    $params->{oauth_nonce} ||= MojoX::OAuth::Util->generate_hex_string(8, 32);
    $params->{oauth_timestamp} ||= time;
    $params->{oauth_version}   ||= '1.0';
    $params->{realm}           ||= $self->realm;

    $params->{oauth_callback} = $args->{callback_url}
      if $args->{callback_url};
    $params->{oauth_token}    = $args->{token}    if $args->{token};
    $params->{oauth_verifier} = $args->{verifier} if $args->{verifier};

    # Initialize signature object
    my $signature = MojoX::OAuth::Signature->new(
        url             => $req->url->to_string,
        method          => $req->method,
        consumer_secret => $self->consumer_secret,
        token_secret    => $args->{token_secret} || $self->token_secret
    );

    # TODO merge query and body params
    # $params = {%$params, ...};

    $signature->sign($params);

    $req->headers->header(
        Authorization => 'OAuth ' . join ',' =>
          map { $_ . '="' . b($params->{$_})->url_escape . '"' }
          sort keys %$params
    );

    warn $req;

    if ($cb) {
        $client->process($tx => sub { $cb->($self->_handle_answer($type => shift)) });
    }
    else {
        return $self->_handle_answer($type => $client->process($tx));
    }
}

sub _handle_answer {
    my $self   = shift;
    my $type   = shift;
    my $client = shift;

    warn $client->res;

    my $clone = $self->clone;
    $clone->client($client);

    my $res = $clone->res;
    return $clone unless $res;

    # Prepare for bad servers
    $res->headers->content_type('application/x-www-form-urlencoded');

    if ($type eq 'request_token' || $type eq 'access_token') {
        use Data::Dumper;
        #warn 'v' x 20;
        #warn Dumper $res->body_params;
        #warn '^' x 20;
        my $token        = $res->body_params->param('oauth_token');
        my $token_secret = $res->body_params->param('oauth_token_secret');

        warn "token=$token";
        warn "token_secret=$token_secret";

        return $clone unless $token && $token_secret;

        $clone->token($token);
        $clone->token_secret($token_secret);

        # Prepare user authorization url
        if ($type eq 'request_token') {
            my $url = Mojo::URL->new->parse($clone->user_authorization_url);
            $url->query(oauth_token => $token);
            $clone->user_authorization_url($url->to_string);
        }
    }
    else {
    }

    $clone->success(1);

    return $clone;
}

1;
