#!/usr/bin/env perl

use strict;
use warnings;

use utf8;

use Test::More tests => 9;

use Mojo::Client::OAuth;

my $client = Mojo::Client::OAuth->new;

my $tx = $client->request_token(
    'https://api.twitter.com/oauth/request_token' => {
        consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98',
        params          => {
            oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
            oauth_callback =>
              'http://localhost:3005/the_dance/process_callback?service_provider_id=11',
            oauth_nonce     => 'QP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk',
            oauth_timestamp => '1272323042'
        }
    }
);
my $header = $tx->req->headers->header('authorization');
is($header, '');
#is($client->signature_base_string,
#'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Fclientuest_token&oauth_callback%3Dhttp%253A%252F%252Flocalhost%253A3005%252Fthe_dance%252Fprocess_callback%253Fservice_provider_id%253D11%26oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DQP70eNmVz8jvdPevU3oJD2AfF7R7odC2XJcn4XlZJqk%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323042%26oauth_version%3D1.0'
#);
#is($client->signing_key, 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&');
#is($client->signature->to_string, '8wUi7m5HFQy76nowoCThusfgB+Q=');

##is_deeply($client->to_headers, {Authorization => "OAuth "});

    #url             => 'https://api.twitter.com/oauth/access_token',
    #consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98',
    #token_secret    => 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA',
    #params          => {
        #oauth_consumer_key     => 'GDdmIQH6jhtmLUypg82g',
        #oauth_token            => '8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc',
        #oauth_signature_method => 'HMAC-SHA1',
        #oauth_nonce            => '9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8',
        #oauth_timestamp        => '1272323047',
        #oauth_verifier => 'pDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY',
        #oauth_version  => '1.0'
    #}
#);
#is($client->signature_base_string,
    #'POST&https%3A%2F%2Fapi.twitter.com%2Foauth%2Faccess_token&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3D9zWH6qe0qG7Lc1telCn7FhUbLyVdjEaL3MO5uHxn8%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272323047%26oauth_token%3D8ldIZyxQeVrFZXFOZH5tAwj6vzJYuLQpl0WUEYtWc%26oauth_verifier%3DpDNg57prOHapMbhv25RNf75lVRd6JDsni1AJJIDYoTY%26oauth_version%3D1.0'
#);
#is($client->signing_key,
    #'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA'
#);
#is($client->signature->to_string, 'PUw/dHA4fnlJYM6RhXk5IU/0fCc=');

    #url             => 'http://api.twitter.com/1/statuses/update.json',
    #consumer_secret => 'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98',
    ##token_secret    => 'x6qpRnlEmW9JbQn4PQVVeVG8ZLPEx6A0TOebgwcuA',
    #token_secret    => 'J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA',
    #params          => {
        #oauth_consumer_key => 'GDdmIQH6jhtmLUypg82g',
        #oauth_token => '819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw',
        #oauth_signature_method => 'HMAC-SHA1',
        #oauth_nonce            => 'oElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y',
        #oauth_timestamp        => '1272325550',
        #oauth_version          => '1.0'
    #},
    #body =>
      #{status => 'setting up my twitter 私のさえずりを設定する'}
#);
#is($client->signature_base_string,
    #'POST&http%3A%2F%2Fapi.twitter.com%2F1%2Fstatuses%2Fupdate.json&oauth_consumer_key%3DGDdmIQH6jhtmLUypg82g%26oauth_nonce%3DoElnnMTQIZvqvlfXM56aBLAf5noGD0AQR3Fmi7Q6Y%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1272325550%26oauth_token%3D819797-Jxq8aYUDRmykzVKrgoLhXSq67TEa5ruc4GJC2rWimw%26oauth_version%3D1.0%26status%3Dsetting%2520up%2520my%2520twitter%2520%25E7%25A7%2581%25E3%2581%25AE%25E3%2581%2595%25E3%2581%2588%25E3%2581%259A%25E3%2582%258A%25E3%2582%2592%25E8%25A8%25AD%25E5%25AE%259A%25E3%2581%2599%25E3%2582%258B'
#);
#is($client->signing_key,
    #'MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98&J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA'
#);
#is($client->signature->to_string, 'yOahq5m0YjDDjfjxHaXEsW9D+X0=');
