#!/usr/bin/env perl

use strict;
use warnings;

use Test::More tests => 9;

use MojoX::OAuth::Parameters;

my $params = MojoX::OAuth::Parameters->new;
is_deeply($params->to_hash, {});
is("$params", "");

$params = MojoX::OAuth::Parameters->new(params => {a => 'b'});
is($params->param('a'), 'b');
is_deeply($params->to_hash, {a => 'b'});
is("$params", "a=b");

$params = MojoX::OAuth::Parameters->new;
$params->params({a => 'b'});
$params->params({a => 'c'});
$params->params({a => [qw/d e/]});
is_deeply($params->to_hash, {a => [qw/b c d e/]});
is_deeply($params->param('a'), [qw/b c d e/]);
is("$params", "a=b&a=c&a=d&a=e");

$params = MojoX::OAuth::Parameters->new;
$params->params({b5 => '=%3D', a3 => 'a', 'c@' => undef, a2 => 'r b'});
$params->params(
    {   realm                  => "Example",
        oauth_consumer_key     => "9djdj82h48djs9d2",
        oauth_token            => "kkk9d7dh3k39sjv7",
        oauth_signature_method => "HMAC-SHA1",
        oauth_timestamp        => "137131201",
        oauth_nonce            => "7d8f3e4a",
        oauth_signature        => "djosJKDKJSD8743243%2Fjdk33klY%3D"
    }
);
$params->params({c2 => undef, a3 => '2 q'});
is($params->to_string,
    "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
);
