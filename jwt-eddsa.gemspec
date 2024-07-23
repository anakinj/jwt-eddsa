# frozen_string_literal: true

require_relative "lib/jwt/eddsa/version"

Gem::Specification.new do |spec|
  spec.name = "jwt-eddsa"
  spec.version = JWT::Eddsa::VERSION
  spec.authors = ["Joakim Antman"]
  spec.email = ["antmanj@gmail.com"]

  spec.summary = "Extension for the jwt gem"
  spec.homepage = 'https://github.com/anakinj/jwt-eddsa'
  spec.license = "MIT"
  spec.required_ruby_version = '>= 2.5'

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = 'https://github.com/anakinj/jwt-eddsa'
  spec.metadata["changelog_uri"] = "https://github.com/anakinj/jwt-eddsablob/v#{JWT::Eddsa::VERSION}/CHANGELOG.md"

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

  # Uncomment to register a new dependency of your gem
  spec.add_dependency "rbnacl", "~> 6.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end