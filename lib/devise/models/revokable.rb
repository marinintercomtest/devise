require 'devise/hooks/revokable'

module Devise
  module Models
    module Revokable
      extend ActiveSupport::Concern

      def self.required_fields(klass)
        ['active_sessions']
      end

      def revoked?(revokable_token)
        !active_sessions.include?(revokable_token)
      end

      def max_revokable_sessions
        self.class.max_revokable_sessions
      end

      private

      module ClassMethods
        Devise::Models.config(self, :max_revokable_sessions)
      end
    end
  end
end
