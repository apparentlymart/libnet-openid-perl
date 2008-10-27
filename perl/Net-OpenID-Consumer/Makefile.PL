use ExtUtils::MakeMaker;
WriteMakefile( 'NAME' => 'Net::OpenID::Consumer',
               'VERSION_FROM' => 'lib/Net/OpenID/Consumer.pm',
               'PREREQ_PM'		=> {
                   'LWP::UserAgent' => 0,
                   'HTTP::Request'  => 0,
                   'MIME::Base64'   => 0,
                   'Digest::SHA1'   => 0,
                   'URI'            => 0,
                   'Time::Local'    => 0,
                   'XML::Simple'    => 0,
                   'Crypt::DH'      => 0.05,
               },
               ($] >= 5.005 ?
                (ABSTRACT_FROM => 'lib/Net/OpenID/Consumer.pm',
                 AUTHOR     => 'Brad Fitzpatrick <brad@danga.com>') : ()),
               );
