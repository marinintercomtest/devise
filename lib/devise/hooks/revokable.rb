Warden::Manager.after_set_user :except => :fetch do |record, warden, options|
  scope = options[:scope]
  env = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable']
    revokable_token = record.activate_revokable_session
    warden.cookies.signed["revokable_token"] = revokable_token
  end
end

Warden::Manager.after_fetch do |record, warden, options|
  scope = options[:scope]
  env   = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable']
    if warden.authenticated?(scope)
      if record.revoked?(warden.cookies.signed["revokable_token"])
        warden.logout(scope)
        throw :warden, :scope => scope, :message => :unauthenticated
      end
    end
  end
end

Warden::Manager.before_logout do |record, warden, options|
  env = warden.request.env

  if record && record.respond_to?(:revoked?) && options[:store] != false && !env['devise.skip_revokable']
    if record.deactivate_revokable_session(warden.cookies.signed["revokable_token"])
      warden.cookies.delete("revokable_token")
    end
  end
end
