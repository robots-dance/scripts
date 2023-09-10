#!/usr/bin/perl -w

use strict;
use Crypt::CBC;
use MIME::Base64;

use constant {
	ENCRYPT_OP => 0,
	DECRYPT_OP => 1
};

my $B64_REGEX = "^[a-zA-Z0-9+=\/]+\$";
my $USAGE = "Usage: ./crypter.pl <key> <operation> <string>" .
	", where:\n" .
	"\tkey - an encryption | decryption key or password,\n" .
	"\toperation - a string with two allowed values: encrypt and decrypt\n" .
	"\tstring - an input text for a processing\n";
die $USAGE if ( @ARGV < 3 );

my $key = $ARGV[ 0 ];
my $operStr = $ARGV[ 1 ];
my $text = $ARGV[ 2 ];
die "incorrect an input text" if ( !( $text =~ $B64_REGEX ) );
my $oper = -1;
if ( $operStr eq "encrypt" ) {
	$oper = ENCRYPT_OP;
}
elsif ( $operStr eq "decrypt" ) {
	$oper = DECRYPT_OP;
}
die "incorrect an operation value" if ( -1 == $oper );

my $cipher = Crypt::CBC->new( -key => $key,
	-cipher => 'Crypt::OpenSSL::AES',
	-keysize => 32 );
my $outputStr = "";
if ( ENCRYPT_OP == $oper )
{
	my $encryptedData = $cipher->encrypt( $text );
	$outputStr = encode_base64( $encryptedData );
}
else
{
	my $encryptedData = decode_base64( $text );
	$outputStr = $cipher->decrypt( $encryptedData );
	if ( !( $outputStr =~ $B64_REGEX ) )
	{
		die "incorrect decrypted data\n";
	}
}
print $outputStr;
