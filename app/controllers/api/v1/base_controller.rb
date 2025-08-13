class Api::V1::BaseController < ActionController::API

  # Protect all routes, requires valid JWT token
  before_action :authenticate_user!

  def authenticate_user
    token = header_token if header_token.present?
    return render json: { error: "Missing token" }, status: :unauthorized unless token

    begin
      decoded = JsonWebToken.decode(token)
      @current_user = User.find(decoded[:user_id])
    rescue JWT::ExpiredSignature
      render json: { error: "Expired token" }, status: :unauthorized
    rescue  JWT::DecodeError
      render json: { error: "Invalid token" }, status: :unauthorized
    end
  end

  private

  def header_token
    request.headers['Authorization'].split(' ').last
  end

  def user_not_authorized(exception)
    render json: {
      error: "Unauthorized #{exception.policy.class.to_s.underscore.camelize}.#{exception.query}"
    }, status: :unauthorized
  end

  def not_found(exception)
    render json: { error: exception.message }, status: :not_found
  end
end
