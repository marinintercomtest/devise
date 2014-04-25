require 'test_helper'

class SessionRevocationTest < ActionDispatch::IntegrationTest

  def revokable_token_signed_cookie
    warden.cookies.signed['revokable_token']
  end

  test 'set revokable_token signed cookie after sign in which is maintained until sign out' do
    get users_path
    assert_nil revokable_token_signed_cookie

    sign_in_as_user
    assert_not_nil revokable_token_signed_cookie

    get users_path
    assert_not_nil revokable_token_signed_cookie

    get destroy_user_session_path
    assert_nil revokable_token_signed_cookie
  end

  test 'user logged out after we explicitly delete the active session' do
    sign_in_as_user

    get users_path
    assert response.code.to_i == 200

    user = User.last
    user.active_sessions.pop
    user.save

    get users_path
    assert response.code.to_i == 302
    assert response.location.end_with? "http://www.example.com/users/sign_in"
  end

  test 'does not revoke user session if the timeoutable module has not yet timed out' do
    sign_in_as_user
    assert_not_nil revokable_token_signed_cookie

    get users_path
    assert_not_nil revokable_token_signed_cookie
  end

  test 'revokes user session if timeoutable module has timed out' do
    user = sign_in_as_user
    get expire_user_path(user)
    assert_not_nil revokable_token_signed_cookie

    get users_path
    assert_nil revokable_token_signed_cookie
  end
end
