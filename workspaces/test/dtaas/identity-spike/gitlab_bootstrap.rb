# Spike S3: seed the throwaway GitLab with an admin API token and the
# users user1 and user2. Run with gitlab-rails runner; values come from
# the environment set in spike.gitlab.overlay.yml. Safe to run again.

admin_token = ENV.fetch('SPIKE_ADMIN_TOKEN')
password = ENV.fetch('SPIKE_USER_PASSWORD')
root = User.find_by_username!('root')

unless PersonalAccessToken.find_by_token(admin_token)
  pat = root.personal_access_tokens.build(
    name: 'spike-s3', scopes: %w[api sudo admin_mode],
    expires_at: 7.days.from_now,
    organization: Organizations::Organization.first
  )
  pat.set_token(admin_token)
  pat.save!
end

%w[user1 user2].each do |name|
  user = User.find_by_username(name)
  unless user
    result = Users::CreateService.new(
      root, username: name, name: name, email: "#{name}@example.org",
            password: password, skip_confirmation: true,
            organization_id: Organizations::Organization.first.id
    ).execute
    user = result.respond_to?(:payload) ? result.payload[:user] : result
    raise "could not create #{name}: #{result.message}" unless user&.persisted?
  end
  # An admin-set password must otherwise be changed at first sign-in.
  user.update!(password_expires_at: nil, password_automatically_set: false)
end

puts 'spike bootstrap done'
