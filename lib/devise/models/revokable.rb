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
        self.active_sessions << revokable_token unless self.active_sessions.include? revokable_token
        self.active_sessions = self.active_sessions.last(max_concurrent_sessions)
        save
        revokable_token
      end

      def deactivate_revokable_session(revokable_token)
        self.active_sessions.delete(revokable_token)
        save
      end

      def revoked?(revokable_token)
        !self.active_sessions.include?(revokable_token)
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
