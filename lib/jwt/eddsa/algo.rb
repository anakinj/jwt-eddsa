# frozen_string_literal: true

module JWT
  module EdDSA
    # EdDSA algorithm implementation
    class Algo
      include JWT::JWA::SigningAlgorithm

      def initialize(alg)
        @alg = alg
      end

      def sign(data:, signing_key:)
        unless signing_key.is_a?(Ed25519::SigningKey)
          raise_sign_error!("Key given is a #{signing_key.class} but needs to be a Ed25519::SigningKey")
        end

        signing_key.sign(data)
      end

      def verify(data:, signature:, verification_key:)
        unless verification_key.is_a?(Ed25519::VerifyKey)
          raise_verify_error!("Key given is a #{verification_key.class} but needs to be a Ed25519::VerifyKey")
        end

        verification_key.verify(signature, data)
      rescue Ed25519::VerifyError
        false
      end

      def header(*)
        { "alg" => "EdDSA" }
      end

      register_algorithm(new("EdDSA"))
      register_algorithm(new("ED25519"))
    end
  end
end
