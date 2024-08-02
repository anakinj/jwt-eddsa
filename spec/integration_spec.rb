# frozen_string_literal: true

require "securerandom"

RSpec.describe "Usage via ruby-jwt" do
  let(:private_key) { RbNaCl::Signatures::Ed25519::SigningKey.new("b" * 32) }
  let(:public_key) { private_key.verify_key }

  let(:payload) { { "pay" => "load" } }

  describe "encoding and decoding" do
    context "when encoding and decoding keys match" do
      it "executes successfully" do
        token = JWT.encode(payload, private_key, "EdDSA")
        expect(JWT.decode(token, public_key, true, algorithm: "EdDSA"))
          .to eq([payload, { "alg" => "EdDSA" }])
      end
    end

    context "when decoding key is wrong" do
      let(:public_key) { RbNaCl::Signatures::Ed25519::SigningKey.new("a" * 32).verify_key }
      it "raises decoding error" do
        token = JWT.encode(payload, private_key, "EdDSA")

        expect do
          JWT.decode(token, public_key, true, algorithm: "EdDSA")
        end.to raise_error(JWT::DecodeError, "Signature verification failed")
      end
    end

    context "when decoding with a private key" do
      it "raises decoding error" do
        token = JWT.encode(payload, private_key, "EdDSA")

        expect do
          JWT.decode(token, private_key, true, algorithm: "EdDSA")
        end.to raise_error(JWT::DecodeError)
      end
    end

    context "when encoding with a public key" do
      it "raises encoding error" do
        expect do
          JWT.encode(payload, public_key, "EdDSA")
        end.to raise_error(JWT::EncodeError)
      end
    end
  end

  describe "OKP JWK usage" do
    let(:jwk)           { JWT::JWK.new(RbNaCl::Signatures::Ed25519::SigningKey.new(SecureRandom.hex)) }
    let(:public_jwks)   { { keys: [jwk.export, { kid: "not_the_correct_one", kty: "oct", k: "secret" }] } }
    let(:signed_token)  { JWT.encode(token_payload, jwk.signing_key, "EdDSA", token_headers) }
    let(:token_payload) { { "data" => "something" } }
    let(:token_headers) { { kid: jwk.kid } }

    it "decodes the token" do
      key_loader = ->(_options) { JSON.parse(JSON.generate(public_jwks)) }
      payload, _header = JWT.decode(signed_token, nil, true,
                                    { algorithms: ["EDDSA"], jwks: key_loader })
      expect(payload).to eq(token_payload)
    end
  end
end
