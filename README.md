# jwt-eddsa

[![Gem Version](https://badge.fury.io/rb/jwt-eddsa.svg)](https://badge.fury.io/rb/jwt-eddsa)
[![Build Status](https://github.com/anakinj/jwt-eddsa/workflows/test/badge.svg?branch=main)](https://github.com/jwt/ruby-jwt/actions)

A library extending the ruby-jwt gem with EdDSA algorithms. Based on [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037).

**NOTE: This gem is still WIP**

Work is currently done in [ruby-jwt](https://github.com/jwt/ruby-jwt/pull/607) to allow extending the algorithms.

Plan is to replace rbnacl with something else in the near future.

## Installation

Will only work with the WIP branch, so adding the following to your the Gemfile should do the trick:
```
gem "jwt", github: "anakinj/ruby-jwt", branch: "extendable-algos"
gem "jwt-eddsa"
```

```
require "jwt/eddsa" # not verified if this actually works
```

## Usage

```ruby
private_key = RbNaCl::Signatures::Ed25519::SigningKey.new("b" * 32)
token = JWT.encode({pay: "load"}, private_key, "EdDSA")
payload, header = JWT.decode(token, private_key.verify_key, true, algorithm: "EdDSA")
```

## Development

```
bundle install
bundle exec rake
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/anakinj/jwt-eddsa. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [code of conduct](https://github.com/anakinj/jwt-eddsa/blob/master/CODE_OF_CONDUCT.md).

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the jwt-eddsa project's codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/[USERNAME]/jwt-eddsa/blob/master/CODE_OF_CONDUCT.md).
