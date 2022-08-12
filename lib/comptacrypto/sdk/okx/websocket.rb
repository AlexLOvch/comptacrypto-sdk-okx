require 'faye/websocket'
require 'base64'
require 'openssl'
require 'json'

module Comptacrypto
  module Sdk
    module Okx
      class WebSocket
        class Error < StandardError; end
        BASE_URL = "wss://ws$subdomain_postfix$.okx.com:8443/ws/v5/$channel_type$"
        OKX_SECRET_KEY = ENV["OKX_SECRET_KEY"]
        OKX_API_KEY = ENV["OKX_API_KEY"]
        OKX_PASSPHRASE = ENV["OKX_PASSPHRASE"]

        AUTH_REQ_TEMPLATE = {
          'op': 'login',
          'args': [
            {
              'apiKey': '$api_key$',
              'passphrase': '$passphrase$',
              'timestamp': '$timestamp$',
              'sign': '$sign$'
            }
          ]
        }.to_json

        COMMAND_TEMPLATE = '{$id$"op":"$op$","args":$args$}'

        # options:
        #   is_test: true/false
        #   is_aws: true/false
        #   channel_type: private/public
        def initialize(options = {})
          @is_test = options[:is_test]
          @is_aws = options[:is_aws]
          @channel_type = options[:channel_type]&.to_sym || :public
          @websocket = create_websocket

          @callbacks_hash = options[:callbacks_hash] || {}
          attach_callbacks if @callbacks_hash.any?
          login if auth_required?
        end

        def subscribe(args:)
          run_command(command: 'subscribe', args: args)
        end

        def unsubscribe(args:)
          run_command(command: 'unsubsubscribe', args: args)
        end

        def place_order(id:, args:)
          run_command(command: 'order', args: args, id: id)
        end

        def cancel_order(id:, args:)
          run_command(command: 'cancel-order', args: args, id: id)
        end

        def run_command(command:, args:, id: nil)
          send_to_websocket(op: command, args: args, id: id)
        end

        def self.run(commands)
          case commands
          when Array
            commands.map do |command_hash|
              new(command_hash[:options]).public_send(command_hash[:command], **command_hash[:args])
            end
          when Hash
            new(commands[:options]).public_send(commands[:command], **commands[:args])
          else
            raise Error, 'Wrong args - array of commands hashes or commands hash is needed'
          end
        end

        def send_to_websocket(op:, args:, id:)
          message = stream_request_data(op: op, args: args, id: id)
          @callbacks_hash[:log]&.call(">> #{message}")
          @websocket.send(message)
        end

        def send_ping
          @callbacks_hash[:log]&.call(">> ping")
          @websocket.send('ping')
        end

        private

        def create_websocket
          Faye::WebSocket::Client.new(stream_url)
        end

        def stream_url
          url = BASE_URL.dup
          subst_hash = {}
          if @is_test
            subst_hash = { subdomain_postfix: 'pap' }
            url = "#{url}?brokerId=9999"
          elsif @is_aws
            subst_hash = { subdomain_postfix: 'aws' }
          else
            subst_hash = { subdomain_postfix: '' }
          end

          substitude(str: url, subst_hash: subst_hash.merge({ channel_type: @channel_type }))
        end

        def attach_callbacks_and_send_to_websocket(op:, args:, id:)
          attach_callbacks
          send_to_websocket(op: op, args: args, id: id)
        end

        def attach_callbacks
          @callbacks_hash.each do |key, method|
            next if %i[log pong].include?(key)

            @websocket.on(key) do |event|
              case key
              when :message
                process_message(message: event)
              else
                method.call(event)
              end
            end
          end
        end

        def stream_request_data(op:, args:, id:)
          args = args.to_json unless args.is_a?(String)
          subst_hash = { op: op, args: args}
          subst_hash[:id] = id ? "\"id\":\"#{id}\"," : ''

          substitude(str: COMMAND_TEMPLATE.dup, subst_hash: subst_hash)
        end

        def process_message(message:)
          methods = @callbacks_hash
          methods[:log]&.call("<< #{message.data}")
          if message.data == 'pong'
            methods[:pong]&.call
            return
          end

          data = JSON.parse(message.data, symbolize_names: true)

          if (data[:event] == 'error')
            methods[:error].call(data)
          else
            methods[:message].call(data)
          end
        end

        def login
          message = stream_auth_request_data
          @callbacks_hash[:log]&.call(">> #{message}")
          @websocket.send(message)
        end

        def auth_required?
          @channel_type.to_sym == :private
        end

        def stream_auth_request_data
          timestamp = Time.now.to_i
          request_template = AUTH_REQ_TEMPLATE.dup
          subst_hash = {
            api_key: OKX_API_KEY,
            timestamp: timestamp,
            passphrase: OKX_PASSPHRASE,
            sign: signature(timestamp)
          }
          substitude(str: request_template, subst_hash: subst_hash)
        end

        def signature(timestamp)
          str = timestamp.to_s + 'GET/users/self/verify'
          Base64.encode64(OpenSSL::HMAC.digest('sha256', OKX_SECRET_KEY, str)).strip
        end

        def substitude(str:, subst_hash:)
          subst_hash.each_pair { |k, v| str.gsub!("$#{k}$", v.to_s) }
          str
        end
      end
    end
  end
end
