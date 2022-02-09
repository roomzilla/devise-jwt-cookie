require 'dry/configurable'
require 'dry/auto_inject'
require 'devise/jwt/cookie/strategy'

# Authentication library
module Devise
  cattr_reader :jwt_cookie_config

  def self.jwt_cookie
    @@jwt_cookie_config = Devise::JWT::Cookie::Config.new
    yield(@@jwt_cookie_config)
    @@jwt_cookie_config.finalize!
  end

  def self.default_jwt_cookie_config
    {
      name: 'access_token',
      secure: false,
      domain: nil
    }.freeze
  end

  add_module(:jwt_cookie_authenticatable, strategy: :jwt_cookie)

  module JWT
    module Cookie
      class Config
        def initialize
          @paths = []
        end

        def []=(path, v)
          @paths.push([path, v])
        end

        def finalize!
          @paths.freeze
        end

        def match(path)
          # TODO: This is very naive matching and may need optimisation if turns out to be to slow.
          _, v = @paths.find { |k, _| k =~ path}
          v
        end
      end
    end
  end
end

require 'devise/jwt/cookie/version'
require 'devise/jwt/cookie/railtie'
require 'devise/jwt/cookie/cookie_helper'
require 'devise/jwt/cookie/middleware'
require 'devise/jwt/cookie/models'
