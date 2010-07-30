package MojoX::OAuth::Util;

use strict;
use warnings;

sub generate_hex_string {
    shift;
    my ($min, $max) = @_;

    my @s = (0 .. 9, 'a' .. 'z', 'A' .. 'Z');

    my $string = '';

    for (1 .. (rand($max - $min) + $min)) {
        $string .= $s[rand($#s)];
    }

    return $string;
}

1;
