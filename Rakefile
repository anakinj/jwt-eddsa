# frozen_string_literal: true

require "bundler/gem_tasks"
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:spec)

require "rubocop/rake_task"

RuboCop::RakeTask.new

task default: %i[spec rubocop]

task :check_version do
  require_relative "lib/jwt/eddsa/version"
  version = ENV.fetch("GEM_VERSION", nil)

  raise "Version mismatch: #{JWT::EdDSA::VERSION} != #{version}" if version != JWT::EdDSA::VERSION
end

Rake::Task[:build].enhance([:check_version]) if ENV["CI"]
