use ExtUtils::MakeMaker;
WriteMakefile( 'NAME' => 'Net::OpenID::Server',
               'VERSION_FROM' => 'lib/Net/OpenID/Server.pm',
               'PREREQ_PM'		=> {
                   'URI'            => 0,
                   'MIME::Base64'   => 0,
                   'Digest::SHA1'   => 0,
# one of:
#                  'Crypt::OpenSSL::DSA' => 0.12,
#                  'Crypt::DSA'          => 0,
               },
               ($] >= 5.005 ?
                (ABSTRACT_FROM => 'lib/Net/OpenID/Server.pm',
                 AUTHOR     => 'Brad Fitzpatrick <brad@danga.com>') : ()),
               );
