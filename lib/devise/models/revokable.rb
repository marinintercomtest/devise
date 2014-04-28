require 'devise/hooks/revokable'

module Devise
  module Models
    module Revokable
      extend ActiveSupport::Concern

      def self.required_fields(klass)
        ['active_sessions']
      end

      def activate_revokable_session
        revokable_token = SecureRandom.hex
        active_sessions << revokable_token unless active_sessions.include? revokable_token
        active_sessions.last(max_concurrent_sessions)
        save
        revokable_token
      end

      def deactivate_revokable_session(revokable_token)
        active_sessions.delete(revokable_token)
        save
      end

      def revoked?(revokable_token)
        !active_sessions.include?(revokable_token)
      end

      def max_concurrent_sessions
        self.class.max_concurrent_sessions
      end

      private

      module ClassMethods
        Devise::Models.config(self, :max_concurrent_sessions)
      end
    end
  end
end
