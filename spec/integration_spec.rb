# frozen_string_literal: true

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
end
