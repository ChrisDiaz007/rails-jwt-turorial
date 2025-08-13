class Api::V1::TokensController < Api::V1::BaseController
  include ActionController::Cookies

  skip_before_action :authenticate_user!, only: [:refresh_token]

  def refresh_token
    # Read from signed HttpOnly cookie (set at login)
    current_refresh = cookies.signed[:refresh_token]
    return render json: { error: 'Missing refresh token' }, status: :unauthorized if current_refresh.blank?

    user = User.find_by(refresh_token: current_refresh)
    unless user && user.refresh_token_expires_at&.future?
      return render json: { error: 'Invalid or expired refresh token' }, status: :unauthorized
    end

    # Rotate refresh token
    new_refresh = SecureRandom.hex(64)
    new_expiry  = 7.days.from_now
    user.update!(refresh_token: new_refresh, refresh_token_expires_at: new_expiry)

    # Reset the HttpOnly cookie with the rotated token
    cookies.signed[:refresh_token] = {
      value: new_refresh,
      httponly: true,
      secure: true,
      same_site: :none,
      expires: new_expiry
    }

    # Issue a new access token (JWT)
    new_access = Warden::JWTAuth::UserEncoder.new.call(user, :user, nil).first

    # Return ONLY the access token (keep refresh token hidden)
    render json: { access_token: new_access }, status: :ok
  end
end
