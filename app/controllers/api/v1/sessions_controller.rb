class Api::V1::SessionsController < Devise::SessionsController
  include RackSessionFix
  include ActionController::Cookies
  respond_to :json

  private

  def respond_with(resource, _opts = {})
    # Devise-jwt issues this access token
    # access_token = request.env['warden-jwt_auth.token']

    # Generates refresh_token and records/stores in DB(server)
    refresh_token = SecureRandom.hex(64)
    resource.update!(refresh_token: refresh_token, refresh_token_expires_at: 7.days.from_now)

    # Set secured HTTP-only cookie for refresh token(frontend cannot read this cookie)
    cookies.signed[:refresh_token] = {
      value: refresh_token,
      httponly: true,
      secure: true,
      same_site: :none,
      expires: 7.days.from_now
    }

    render json: {
      status: {code: 200, message: 'Logged in successfully.'},
      data: UserSerializer.new(resource).serializable_hash[:data][:attributes],
      # access_token: access_token,
      # refresh_token: refresh_token,
    }, status: :ok
  end

  def respond_to_on_destroy
    if current_user
      # Clears refresh token on logout, and clears out expiration date from DB
      current_user.update(refresh_token: nil, refresh_token_expires_at: nil)
      # Delete the HttpOnly refresh token cookies for all routes; .
      cookies.delete(:refresh_token, path: "/api/v1/refresh_token", same_site: :none)

      render json: {
        status: 200,
        message: "logged out successfully"
      }, status: :ok
    else
      render json: {
        status: 401,
        message: "Couldn't find an active session."
      }, status: :unauthorized
    end
  end

end
