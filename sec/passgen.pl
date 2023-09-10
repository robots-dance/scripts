#!/usr/bin/perl

=pod
	This script can generate passwords
	
	Input params:
		1 - password length (required) 
		2 - passwords count (defaults 1)
=cut

use strict;

sub generate_str
{
	return undef if (@_ != 3);
	my ($min_len, $max_len, $alpha) = @_;
	my $len = int rand($max_len - $min_len + 1) + $min_len;
	my $result = "";
	my $alpha_size = length($alpha);
	for (my $i = 0; $i < $len; $i++)
	{
		my $index = int rand($alpha_size);
		$result .= substr($alpha, $index, 1);
	}
	return $result;
}

my $pass_amount = 1;
my $pass_len = -1;
if (@ARGV)
{
	$pass_len = $ARGV[0];
	if (@ARGV >= 2)
	{
		$pass_amount = $ARGV[1];
	 	if ($pass_amount <= 0) {
			die "incorrect passwords count";
		}
	}
}
if ($pass_len <= 0) {
	die "incorrect password length";
}

my $ALPHA = "";
$ALPHA .= "0123456789";
$ALPHA .= "!@#;%^:&*-_=+";
$ALPHA .= "QWERTYUIOPASDFGHJKLZXCVBNM";
$ALPHA .= "qwertyuiopasdfghjklzxcvbnm";

for (my $i = 0; $i < $pass_amount; $i++)
{
	print generate_str($pass_len, $pass_len, $ALPHA), "\n";
}
