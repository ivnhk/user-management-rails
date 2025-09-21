class RemovePhoneNumberAndPositionFromUsers < ActiveRecord::Migration[8.0]
  def change
    remove_column :users, :phone_number, :string
    remove_column :users, :position, :string
  end
end
