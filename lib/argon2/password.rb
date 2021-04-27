# frozen_string_literal: true

module Argon2
  ##
  # Front-end API for the Argon2 module.
  #
  class Password
    # Used as the default time cost if one isn't provided when calling
    # Argon2::Password.create
    DEFAULT_T_COST = 2
    # Used to validate the minimum acceptable time cost
    MIN_T_COST = 1
    # Used to validate the maximum acceptable time cost
    MAX_T_COST = 750
    # Used as the default memory cost if one isn't provided when calling
    # Argon2::Password.create
    DEFAULT_M_COST = 16
    # Used to validate the minimum acceptable memory cost
    MIN_M_COST = 3
    # Used to validate the maximum acceptable memory cost
    MAX_M_COST = 31
    # Used as the default parallelism cost if one isn't provided when calling
    # Argon2::Password.create
    DEFAULT_P_COST = 1
    # Used to validate the minimum acceptable parallelism cost
    MIN_P_COST = 1
    # Used to validate the maximum acceptable parallelism cost
    MAX_P_COST = 8
    # The complete Argon2 digest string (not to be confused with the checksum).
    #
    # For a detailed description of the digest format, please see:
    # https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md
    attr_reader :digest
    # The hash portion of the stored password hash. This is Base64 encoded by
    # default.
    attr_reader :checksum
    # The salt of the stored password hash. This is Base64 encoded by default.
    #
    # To retrieve the original salt:
    #
    #    require 'base64'
    #
    #    argon2 = Argon2::Password.new(digest)
    #
    #    argon2.salt
    #    => Base64 encoded salt
    #    Base64.decode64(argon2.salt)
    #    => original salt
    attr_reader :salt
    # Variant used (argon2i / argon2d / argon2id)
    attr_reader :variant
    # The version of the argon2 algorithm used to create the hash.
    attr_reader :version
    # The time cost factor used to create the hash.
    attr_reader :t_cost
    # The memory cost factor used to create the hash.
    attr_reader :m_cost
    # The parallelism cost factor used to create the hash.
    attr_reader :p_cost

    ##
    # Class methods
    #
    class << self
      ##
      # Takes a user provided password and returns an Argon2::Password instance
      # with the resulting Argon2 hash.
      #
      # Usage:
      #
      #    Argon2::Password.create(password)
      #    Argon2::Password.create(password, t_cost: 4, m_cost: 20)
      #    Argon2::Password.create(password, secret: pepper)
      #    Argon2::Password.create(password, m_cost: 17, secret: pepper)
      #
      # Currently available options:
      #
      # * :t_cost
      # * :m_cost
      # * :p_cost
      # * :secret
      #
      def create(password, options = {})
        raise Argon2::Errors::InvalidPassword unless password.is_a?(String)

        t_cost = options[:t_cost] || DEFAULT_T_COST
        m_cost = options[:m_cost] || DEFAULT_M_COST
        p_cost = options[:p_cost] || DEFAULT_P_COST

        raise Argon2::Errors::InvalidTCost if t_cost < MIN_T_COST || t_cost > MAX_T_COST
        raise Argon2::Errors::InvalidMCost if m_cost < MIN_M_COST || m_cost > MAX_M_COST
        raise Argon2::Errors::InvalidPCost if p_cost < MIN_P_COST || p_cost > MAX_P_COST

        salt = Engine.saltgen
        secret = options[:secret]

        Argon2::Password.new(
          Argon2::Engine.hash_argon2id_encode(
            password, salt, t_cost, m_cost, p_cost, secret
          )
        )
      end

      ##
      # Regex to validate if the provided String is a valid Argon2 hash output.
      #
      # Supports 1 and argon2id formats.
      #
      def valid_hash?(digest)
        Argon2::HashFormat.valid_hash?(digest)
      end

      ##
      # Takes a password, Argon2 hash, and optionally a secret, then uses the
      # Argon2 C Library to verify if they match.
      #
      # Also accepts passing another Argon2::Password instance as the password,
      # in which case it will compare the final Argon2 hash for each against
      # each other.
      #
      # Usage:
      #
      #    Argon2::Password.verify_password(password, argon2_hash)
      #    Argon2::Password.verify_password(password, argon2_hash, secret)
      #
      def verify_password(password, digest, secret = nil)
        digest = digest.to_s
        if password.is_a?(Argon2::Password)
          password == Argon2::Password.new(digest)
        else
          Argon2::Engine.argon2_verify(password, digest, secret)
        end
      end
    end

    ######################
    ## Instance Methods ##
    ######################

    ##
    # Initialize an Argon2::Password instance using any valid Argon2 digest.
    #
    def initialize(digest)
      digest = digest.to_s

      # FIXME: Behavior duplicated by HashFormat guard clause, remove here?
      raise Argon2::Errors::InvalidHash unless valid_hash?(digest)

      # Split the digest into its component pieces
      split_digest = split_hash(digest)
      # Assign each piece to the Argon2::Password instance
      @digest   = digest
      @variant  = split_digest[:variant]
      @version  = split_digest[:version]
      @t_cost   = split_digest[:t_cost]
      @m_cost   = split_digest[:m_cost]
      @p_cost   = split_digest[:p_cost]
      @salt     = split_digest[:salt]
      @checksum = split_digest[:checksum]
    end

    ##
    # Helper function to allow easily comparing an Argon2::Password against the
    # provided password and secret.
    #
    def matches?(password, secret = nil)
      self.class.verify_password(password, digest, secret)
    end

    ##
    # Compares two Argon2::Password instances to see if they come from the same
    # digest/hash.
    #
    def ==(other)
      # TODO: Should this return false instead of raising an error?
      unless other.is_a?(Argon2::Password)
        raise ArgumentError,
              'Can only compare an Argon2::Password against another Argon2::Password'
      end

      digest == other.digest
    end

    ##
    # Converts an Argon2::Password instance into a String.
    #
    def to_s
      digest.to_s
    end

    ##
    # Converts an Argon2::Password instance into a String.
    #
    def to_str
      digest.to_str
    end

    private

    ##
    # Helper method to allow checking if a hash is valid in the initializer.
    #
    def valid_hash?(digest)
      self.class.valid_hash?(digest)
    end

    ##
    # Helper method to extract the various values from a digest into attributes.
    #
    def split_hash(digest)
      hash_format = Argon2::HashFormat.new(digest)
      # Undo the 2^m_cost operation when encoding the hash to get the original
      # m_cost input back.
      input_m_cost = Math.log2(hash_format.m_cost).to_i

      {
        variant: hash_format.variant,
        version: hash_format.version,
        t_cost: hash_format.t_cost,
        m_cost: input_m_cost,
        p_cost: hash_format.p_cost,
        salt: hash_format.salt,
        checksum: hash_format.checksum
      }
    end
  end
end
