use ExtUtils::MakeMaker;
WriteMakefile( 'NAME' => 'Net::OpenID::Common',
               'VERSION_FROM' => 'lib/Net/OpenID/Common.pm',
               'PREREQ_PM'		=> {
                   'LWP::UserAgent' => 0,
                   'HTTP::Request'  => 0,
                   'HTTP::Status'  => 0,
                   'XML::Simple'    => 0,
                   'Time::Local'    => 0,
                   'Digest::SHA1'    => 0,
                   'MIME::Base64'    => 0,
                   'Math::BigInt'    => 0,
               },
               ($] >= 5.005 ?
                (ABSTRACT_FROM => 'lib/Net/OpenID/Common.pm',
                 AUTHOR     => 'Martin Atkins <mart@degeneration.co.uk>') : ()),
               );
