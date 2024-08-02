# frozen_string_literal: true

require_relative "lib/jwt/eddsa/version"

Gem::Specification.new do |spec|
  spec.name = "jwt-eddsa"
  spec.version = JWT::EdDSA::VERSION
  spec.authors = ["Joakim Antman"]
  spec.email = ["antmanj@gmail.com"]

  spec.summary = "jwt EdDSA algorithm extension"
  spec.description = "Extends the ruby-jwt gem with EdDSA signing, verification and JWK importing/exporting"
  spec.homepage = "https://github.com/anakinj/jwt-eddsa"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.5"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/anakinj/jwt-eddsa"
  spec.metadata["changelog_uri"] = "https://github.com/anakinj/jwt-eddsa/blob/v#{JWT::EdDSA::VERSION}/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "base64"
  spec.add_dependency "jwt", "> 2.8.2"
  spec.add_dependency "rbnacl", "~> 6.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
  spec.metadata["rubygems_mfa_required"] = "true"
end
