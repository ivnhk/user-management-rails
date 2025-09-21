class User < ApplicationRecord
  # Name validations - letters only, max 64 characters
  validates :first_name, presence: true,
            format: { with: /\A[a-zA-Z\s]+\z/, message: "can only contain letters and spaces" },
            length: { maximum: 64 }
  validates :last_name, presence: true,
            format: { with: /\A[a-zA-Z\s]+\z/, message: "can only contain letters and spaces" },
            length: { maximum: 64 }

  # Email validations - real email format, max 64 characters, unique
  validates :email, presence: true, 
            format: { with: /\A[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\z/, message: "must be a valid email address with proper domain" }, 
            uniqueness: { case_sensitive: false },
            length: { maximum: 64 }

  # Phone validation - valid phone number with country code
  validates :phone_number,
            format: { with: /\A\+[1-9]\d{1,14}\z/, message: "must be a valid phone number with country code (e.g., +1234567890)" },
            allow_blank: true

  # Position validation
  validates :position, length: { maximum: 100 }

  # Normalize email to lowercase before saving
  before_save :normalize_email

  private

  def normalize_email
    self.email = email&.strip&.downcase
  end
end
