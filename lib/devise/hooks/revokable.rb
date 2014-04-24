Warden::Manager.after_set_user :except => :fetch do |record, warden, options|
  scope = options[:scope]
  env = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable']
    revokable_token = SecureRandom.hex
    record.active_sessions << revokable_token unless record.active_sessions.include? revokable_token
    record.active_sessions.last(record.max_concurrent_sessions)
    record.save
    warden.cookies.signed["revokable_token"] = revokable_token
  end
end

Warden::Manager.after_fetch do |record, warden, options|
  scope = options[:scope]
  env   = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable']
    if warden.authenticated?(scope)
      revokable_token = warden.cookies.signed["revokable_token"]
      if record.revoked?(revokable_token)
        warden.logout(scope)
        throw :warden, :scope => scope, :message => :unauthenticated
      end
    end
  end
end

Warden::Manager.before_logout do |record, warden, options|
  env = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable`']
    revokable_token = warden.cookies.signed["revokable_token"]
    record.active_sessions.delete(revokable_token)
    record.save
    warden.cookies.delete("revokable_token")
  end
end
