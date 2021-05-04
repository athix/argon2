# frozen_string_literal: true

##
# This Ruby Gem provides FFI bindings and a simplified interface to the Argon2
# algorithm.
#
# Argon2 is the official winner of the Password Hashing Competition, a several
# year project to identify a successor to bcrypt/PBKDF/scrypt methods of
# securely storing passwords.
#
# This is an independent project and not official from the PHC team.
#
module Argon2
  autoload :Constants,  'argon2/constants'
  autoload :Error,      'argon2/errors'
  autoload :Errors,     'argon2/errors'
  autoload :ERRORS,     'argon2/errors'
  autoload :Ext,        'argon2/engine'
  autoload :Engine,     'argon2/engine'
  autoload :VERSION,    'argon2/version'
  autoload :HashFormat, 'argon2/hash_format'
  autoload :Password,   'argon2/password'
end
