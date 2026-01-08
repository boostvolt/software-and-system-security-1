#!/usr/bin/perl

while (<>) {
	chop;
	$w[$#w + 1] = $_;
}

foreach $a (@w) {
	foreach $b (@w) {
		if((substr($a, 0, 1) ne '#') && (substr($b, 0, 1) ne '#')) { 
			$al = lcfirst($a);
			$bl = lcfirst($b);
			$A = ucfirst($a);
			$B = ucfirst($b);
			print "$al$bl\n";
			print "$A$bl\n";
			print "$al$B\n";
			print "$A$B\n";
		}
	}
}
