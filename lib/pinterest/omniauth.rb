require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Pinterest < OmniAuth::Strategies::OAuth2
      option :client_options, {
        site:          'https://api.pinterest.com/',
        authorize_url: 'https://api.pinterest.com/oauth/',
        token_url:     'https://api.pinterest.com/v1/oauth/token'
      }

      option :fields, 'id,first_name,last_name,url,username'

      def request_phase
        options[:scope] ||= 'read_public,write_public'
        options[:response_type] ||= 'token'
        super
      end

      uid { raw_info['id'] }

      info { raw_info }

      def raw_info
        @raw_info ||= access_token.get('/v1/me/', params: { fields: options.fields }).parsed['data']
      end

      def ssl?
        true
      end
    end
  end
end
