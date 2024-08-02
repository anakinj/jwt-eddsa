# frozen_string_literal: true

module JWT
  module EdDSA
    module JWK
      # https://datatracker.ietf.org/doc/html/rfc8037
      class OKP < ::JWT::JWK::KeyBase
        KTY  = "OKP"
        KTYS = [KTY, JWT::EdDSA::JWK::OKP, RbNaCl::Signatures::Ed25519::SigningKey,
                RbNaCl::Signatures::Ed25519::VerifyKey].freeze
        OKP_PUBLIC_KEY_ELEMENTS = %i[kty n x].freeze
        OKP_PRIVATE_KEY_ELEMENTS = %i[d].freeze

        def initialize(key, params = nil, options = {})
          params ||= {}
          # For backwards compatibility when kid was a String
          params = { kid: params } if params.is_a?(String)

          key_params = extract_key_params(key)

          params = params.transform_keys(&:to_sym)
          check_jwk_params!(key_params, params)
          super(options, key_params.merge(params))
        end

        def verify_key
          return @verify_key if defined?(@verify_key)

          @verify_key = verify_key_from_parameters
        end

        def signing_key
          return @signing_key if defined?(@signing_key)

          @signing_key = signing_key_from_parameters
        end

        def key_digest
          ::JWT::JWK::Thumbprint.new(self).to_s
        end

        def private?
          !signing_key.nil?
        end

        def members
          OKP_PUBLIC_KEY_ELEMENTS.each_with_object({}) { |i, h| h[i] = self[i] }
        end

        def export(options = {})
          exported = parameters.clone
          unless private? && options[:include_private] == true
            exported.reject! do |k, _|
              OKP_PRIVATE_KEY_ELEMENTS.include?(k)
            end
          end
          exported
        end

        private

        def extract_key_params(key) # rubocop:disable Metrics/MethodLength
          case key
          when JWT::JWK::KeyBase
            key.export(include_private: true)
          when RbNaCl::Signatures::Ed25519::SigningKey
            @signing_key = key
            @verify_key = key.verify_key
            parse_okp_key_params(@verify_key, @signing_key)
          when RbNaCl::Signatures::Ed25519::VerifyKey
            @signing_key = nil
            @verify_key = key
            parse_okp_key_params(@verify_key)
          when Hash
            key.transform_keys(&:to_sym)
          else
            raise ArgumentError,
                  "key must be of type RbNaCl::Signatures::Ed25519::SigningKey, " \
                  "RbNaCl::Signatures::Ed25519::VerifyKey " \
                  "or Hash with key parameters"
          end
        end

        def check_jwk_params!(key_params, _given_params)
          return if key_params[:kty] == KTY

          raise JWT::JWKError,
                "Incorrect 'kty' value: #{key_params[:kty]}, expected #{KTY}"
        end

        def parse_okp_key_params(verify_key, signing_key = nil)
          params = {
            kty: KTY,
            crv: "Ed25519",
            x: ::Base64.urlsafe_encode64(verify_key.to_bytes, padding: false)
          }

          params[:d] = ::Base64.urlsafe_encode64(signing_key.to_bytes, padding: false) if signing_key

          params
        end

        def verify_key_from_parameters
          RbNaCl::Signatures::Ed25519::VerifyKey.new(::Base64.urlsafe_decode64(self[:x]))
        end

        def signing_key_from_parameters
          return nil unless self[:d]

          RbNaCl::Signatures::Ed25519::SigningKey.new(::Base64.urlsafe_decode64(self[:d]))
        end

        class << self
          def import(jwk_data)
            new(jwk_data)
          end
        end
      end
    end
  end
end
