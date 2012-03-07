use ExtUtils::MakeMaker;

use Config;
my $Makefile	= 'Makefile.tmp';

WriteMakefile(
	'NAME'	    => 'IO::Stty',
	'VERSION_FROM' => 'Stty.pm',
	'MAKEFILE'	=> $Makefile,
	'linkext'	=> {LINKTYPE => ''},
	'dist'		=> {
				'COMPRESS'	=>'gzip',
				'SUFFIX'	=>'gz'
			},
);
