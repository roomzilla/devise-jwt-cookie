module Devise
  module JWT
    module Cookie
      class CookieHelper
        
        def initialize(env)
          path = env['PATH_INFO']
          @config = config_for(path)
        end

        def build(token)
          if token.nil?
            remove_cookie
          else
            create_cookie(token)
          end
        end

        def read_from(cookies)
          name = @config[:name]
          cookies[name]
        end

        private

        def create_cookie(token)
          jwt = Warden::JWTAuth::TokenDecoder.new.call(token)
          res = {
            value: token,
            path: '/',
            httponly: true,
            secure: @config[:secure],
            expires: Time.at(jwt['exp'].to_i)
          }
          res[:domain] = @config[:domain] if @config[:domain].present?
          [@config[:name], res]
        end

        def remove_cookie
          res = {
            value: nil,
            path: '/',
            httponly: true,
            secure: @config[:secure],
            max_age: '0',
            expires: Time.at(0)
          }
          res[:domain] = @config[:domain] if @config[:domain].present?
          [@config[:name], res]
        end
        
        def config_for(path)
          Devise.jwt_cookie_config.match(path) || Devise.default_jwt_cookie_config
        end
      end
    end
  end
end
