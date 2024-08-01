# frozen_string_literal: true

require "jwt"
require_relative "eddsa/version"

module JWT
  # EdDSA algorithm implementation
  module Eddsa
    include JWT::JWA::Algorithm

    register_algorithm("EdDSA")

    class << self
      def sign(_algorithm, msg, key)
        unless key.is_a?(RbNaCl::Signatures::Ed25519::SigningKey)
          raise_sign_error!("Key given is a #{key.class} but needs to be a RbNaCl::Signatures::Ed25519::SigningKey")
        end

        key.sign(msg)
      end

      def verify(_algorithm, public_key, signing_input, signature)
        unless public_key.is_a?(RbNaCl::Signatures::Ed25519::VerifyKey)
          raise_verify_error!("Key given is a #{public_key.class} but needs to be a RbNaCl::Signatures::Ed25519::VerifyKey")
        end

        public_key.verify(signature, signing_input)
      rescue RbNaCl::CryptoError
        false
      end
    end
  end
end
