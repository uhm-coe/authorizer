# Changelog

= 3.9.1 =
* Fix for global $wp_roles unavailable in some multisite contexts leading to a fatal error.

= 3.9.0 =
* Tested up to WordPress 6.6.
* Fix ldap_connect() deprecation notice in PHP 8.3. Props @svyatoslavnetrunner for the [code](https://wordpress.org/support/topic/php8-ldap_connect-deprecation/)!
* Trim whitespace from Google Client ID and Secret. Props @JSLittlefield for the [suggestion](https://wordpress.org/support/topic/solved-white-screen-using-google-authentication/)!
* Allow defining Google Client ID and OAuth2 Client ID via filters (`authorizer_google_client_id` and `authorizer_oauth2_client_id`) or wp-config.php constants (`define( 'AUTHORIZER_GOOGLE_CLIENT_ID', '...' );` and `define( 'AUTHORIZER_OAUTH2_CLIENT_ID', '...' );`) to support integrations with third-party secrets managers (or simply to keep the secrets out of the database in plaintext). Client Secrets were already added in version 3.6.1, this update adds filters and constants for the Client IDs. Props @nks04747 for the [suggestion](https://wordpress.org/support/topic/storing-oauth2-client-id-in-wp-config/)!
* Fix Google/LDAP/Oauth2 secrets fields not hiding in Authorizer Settings if overridden by a filter or constant, and the external service is disabled.
* Fix warning about duplicate DOM IDs in Authorizer Settings.
* Update composer dependencies: guzzlehttp/guzzle (7.8.1 => 7.9.1); guzzlehttp/promises (2.0.2 => 2.0.3); guzzlehttp/psr7 (2.6.2 => 2.7.0); monolog/monolog (2.9.2 => 2.9.3); paragonie/constant_time_encoding (v2.6.3 => v2.7.0); phpseclib/phpseclib (3.0.37 => 3.0.39); psr/http-factory (1.0.2 => 1.1.0); symfony/deprecation-contracts (v2.5.2 => v2.5.3).

= 3.8.5 =
* Fix database migrations re-running in complex multisite multi-network setups. Props @mpemburn for the research (and endurance) to discover the [root cause](https://wordpress.org/support/topic/numerous-set_default_options-calls-cause-site-to-crash/)!

= 3.8.4 =
* Update French translations. Props @julienlusson!
* Fix TinyMCE settings fields sometimes uneditable. Props dorianborovina for the detailed [bug report](https://github.com/uhm-coe/authorizer/issues/152)!
* Remove package-lock.json (development dependency).

= 3.8.3 =
* Disable caching on the Authorizer Settings page to reduce memory footprint. Props @timkite for the [report](https://wordpress.org/support/topic/authorizer-admin-page-using-too-much-memory/)!
* Add zh_CN translation. Props pinke for the [pull request](https://github.com/uhm-coe/authorizer/pull/150)!
* Update translatable strings.

= 3.8.2 =
* Fix new user always assigned default role on first login instead of role in approved list. Bug introduced in 3.8.1. Props @melidonis for the [report](https://wordpress.org/support/topic/new-users-role-reverted-to-subscriber/)!

= 3.8.1 =
* Add missing OAuth2 automatic login multisite option.

= 3.8.0 =
* Block the WordPress lost password endpoint if Authorizer is configured to disable WordPress logins. Props @manakuke for the [discovery](https://wordpress.org/support/topic/remove-block-forgot-password-page/)!
* Allow immediately showing OAuth2 login form if it’s the only external service enabled and WordPress logins are hidden (e.g., skip showing the “Log In with OAuth2” button on wp-login.php). Props @dblas for the [suggestion](https://wordpress.org/support/topic/bypassing-the-wp-log-on-screen/)!
* Generate performant translations from .mo files. See: https://make.wordpress.org/core/2024/02/27/i18n-improvements-6-5-performant-translations/
* Fix role change in authorizer_custom_role filter not synced to approved list. Props mdebski for the [issue and research](https://github.com/uhm-coe/authorizer/issues/149)!
* Fix duplicate delete option during uninstall routine.
* Fix unneeded role dropdown for blocked users (since blocked users get their roles removed, this was causing php warnings on checking strlen() on the null role value).
* Tested up to WordPress 6.5.3.

= 3.7.1 =
* Replace jquery.multi-select composer dependency with local copy (since the composer package was removed). Props @julienlusson the catch!

= 3.7.0 =
* Drop support for PHP 7.2 and 7.3. Minimum PHP version is now 7.4 (due to google-api-php-client requirements).
* Simple History now logs a different message if the global lockout is triggered on a nonexistent user. Props @TuringTux for the [pull request](https://github.com/uhm-coe/authorizer/pull/143)!
* Update French translations. Props @julienlusson!
* Fix incrementing the wrong failed login counter if failed login used an email address instead of a username. Now the specific user counter is incremented instead of the global/nonexistent user counter. Props @TuringTux for the [report and investigation](https://github.com/uhm-coe/authorizer/issues/138)!
* Fix for PHP warning when viewing admin pages in Pressbooks.
* Fix for PHP warning about missing `ldap_test_user` setting on some multisite installs.
* Remove old jQuery library from multi-select package (has XSS vulnerabilities).
* Update composer dependencies: google/apiclient (v2.13.2 => v2.14.0); thenetworg/oauth2-azure (v2.1.1 => v2.2.2); components/jquery (3.6.0 => v3.7.1); google/apiclient-services (v0.297.0 => v0.302.0); guzzlehttp/guzzle (7.5.1 => 7.8.1); guzzlehttp/promises (1.5.2 => 2.0.2); guzzlehttp/psr7 (2.5.0 => 2.6.2); monolog/monolog (2.9.1 => 2.9.2); phpseclib/phpseclib (3.0.19 => 3.0.37); psr/http-client (1.0.2 => 1.0.3).

= 3.6.3.1 =
* Compatibility fix for Oxygen Builder.

= 3.6.3 =
* Update helper text for the LDAP STARTTLS option. Props @TuringTux for the [pull request](https://github.com/uhm-coe/authorizer/pull/132)!
* Update French translations. Props @julienlusson!
* Update composer dependencies (phpseclib/phpseclib 3.0.18 => 3.0.19; psr/http-message 1.0.1 => 1.1; psr/http-factory 1.0.1 => 1.0.2; guzzlehttp/psr7 2.4.3 => 2.5.0; apereo/phpcas 1.6.0 => 1.6.1; firebase/php-jwt v6.3.2 => v6.4.0; google/apiclient v2.13.0 => v2.13.2; google/apiclient-services v0.285.0 => v0.297.0; google/auth v1.25.0 => v1.26.0; guzzlehttp/guzzle 7.5.0 => 7.5.1; league/oauth2-client 2.6.1 => 2.7.0; monolog/monolog 2.8.0 => 2.9.1; psr/http-client 1.0.1 => 1.0.2).
* Fix: Remove private pages from search results and archives if visitor is an anonymous user and site is configured to only allow logged in users to see the site. Props @ramrajone for the bug report!
* Fix: Allow minor clock drift (30s) between the WordPress server and Google's server when processing Google logins.
* Tested up to WordPress 6.2.

= 3.6.2 =
* Performance tweaks during Authorizer updates on large multisites.
* Ensure lockout values are integers for invalid login attempts (php8 compatibility).
* Check for existence of super admin roles before adding super admin to approved list on multisite activation.
* Update French translations. Props @julienlusson!
* Allow defining LDAP Directory User and Password via filters (`authorizer_ldap_user` and `authorizer_ldap_password`) or wp-config.php constants (`define( 'AUTHORIZER_LDAP_USER', '...' );` and `define( 'AUTHORIZER_LDAP_PASSWORD', '...' );`) to support integrations with third-party secrets managers (or simply to keep the secrets out of the WordPress database).
* Allow `authorizer_custom_role` filter on admin logins.

= 3.6.1 =
* Allow defining Google Client Secret and OAuth2 Client Secret via filters (`authorizer_google_client_secret` and `authorizer_oauth2_client_secret`) or wp-config.php constants (`define( 'AUTHORIZER_GOOGLE_CLIENT_SECRET', '...' );` and `define( 'AUTHORIZER_OAUTH2_CLIENT_SECRET', '...' );`) to support integrations with third-party secrets managers (or simply to keep the secrets out of the database in plaintext).
* Handle arrays in CAS attribute for first/last name.
* Fix: conflict with W3 Total Cache (when using Azure CDN provider that uses an older guzzlehttp library). [Check status](https://github.com/W3EDGE/w3-total-cache/issues/642)
* Fix: only clean up Google session on logout if it exists.
* Fix: Remove all plugin options in database upon deletion/uninstall.
* Fix: Handle Google login error triggered when a stale browser window sends a login request.
* Upgrade composer dependencies (firebase/php-jwt v6.3.1 => v6.3.2, google/apiclient v2.12.6 => v2.13.0, google/apiclient-services v0.272.1 => v0.285.0, google/auth v1.23.1 => v1.25.0, phpseclib/phpseclib 3.0.17 => 3.0.18).
* Mention OAuth2 support in readme.txt.
* Update translatable strings.

= 3.6.0 =
* Security: update to [phpCAS 1.6.0](https://github.com/apereo/phpCAS/releases/tag/1.6.0) to address CVE-2022-39369.
* Update composer dependencies (google/apiclient-services 0.271.0 => 0.272.1; google/auth 1.23.0 => 1.23.1; firebase/php-jwt 6.3.0 => 6.3.1; guzzlehttp/psr7 2.4.1 => 2.4.3; phpseclib/phpseclib 3.0.16 => 3.0.17).
* Fix CAS logouts on proxied CAS servers.
* Set default values for missed multisite option ldap_test_user.
* Respect redirect_to param to wp-login.php with Azure logins. Props @manakuke for discovering the [issue](https://github.com/uhm-coe/authorizer/commit/a3d28a91c4ef6bdb32a567f4e5073ed250577ee3)!

= 3.5.0 =
* Migrate Google Sign-In to Google Identity Services library. Details [here](https://developers.google.com/identity/gsi/web/guides/migration).
* Fix inconsistent labels by network users in the approved list (WordPress multisite).
* Update composer dependencies (google/apiclient-services v0.269.0 => v0.271.0).

= 3.4.2 =
* Update French translations. Props @julienlusson!
* Fix password reset for WordPress users when "Immediately redirect to CAS login form." Props @pkarjala for the [fix](https://github.com/uhm-coe/authorizer/issues/121)!
* Upgrade composer dependencies (firebase/php-jwt 5.5.1 => 6.3.0; google/apiclient-services v0.254.0 => v0.269.0; google/auth v1.21.1 => v1.23.0; guzzlehttp/guzzle 7.4.5 => 7.5.0; guzzlehttp/promises 1.5.1 => 1.5.2; guzzlehttp/psr7 2.4.0 => 2.4.1; monolog/monolog 2.7.0 => 2.8.0; phpseclib/phpseclib 3.0.14 => 3.0.16; symfony/deprecation-contracts 2.5.1 => 2.5.2; thenetworg/oauth2-azure 2.0.1 => v2.1.1).

= 3.4.1 =
* Add setting to support CAS servers behind proxies. Props @slyraskal for the [pull request](https://github.com/uhm-coe/authorizer/pull/117)!

= 3.4.0 =
* Upgrade guzzlehttp from 7.4.2 to 7.4.5.
* Upgrade composer dependencies (apereo/phpcas 1.4.0 => 1.5.0; google/apiclient v2.12.4 => v2.12.6; google/apiclient-services v0.246.0 => v0.254.0; google/auth v1.21.0 => v1.21.1; monolog/monolog 2.5.0 => 2.7.0; paragonie/constant_time_encoding 2.5.0 => 2.6.3).
* Authorizer now requires PHP 7.2 or higher (phpCAS requirement).

= 3.3.3 =
* Add multisite option to prevent subsites from overriding multisite settings.
* Allow LDAP bind as user logging in before attempting anonymous bind (by using the [username] wildcard in the LDAP Directory User settings field).
* Add LDAP test connection to Authorizer multisite settings.
* Tested up to WordPress 6.0.
* Update translatable strings.
* Update French translations. Props @julienlusson!

= 3.3.2 =
* Attempt LDAP bind as user logging in if directory user credentials not provided or incorrect.
* Fixed logged errors if LDAP search base couldn't be found (error only shows in LDAP test connection now).
* Fixed LDAP test connection password saved in database.
* Upgrade composer dependencies (google/apiclient v2.12.2 => v2.12.4; google/apiclient-services v0.242.0 => v0.246.0; google/auth v1.19.0 => v1.21.0; monolog/monolog 2.4.0 => 2.5.0).

= 3.3.1 =
* Upgrade composer dependencies (firebase/php-jwt v5.4.0 => v5.5.1; google/apiclient v2.11.0 => v2.12.2; google/apiclient-services v0.213.0 => v0.242.0; google/auth v1.18.0 => v1.19.0; guzzlehttp/guzzle 7.3.0 => 7.4.2; guzzlehttp/promises 1.4.1 => 1.5.1; league/oauth2-client 2.6.0 => 2.6.1; monolog/monolog 2.3.4 => 2.4.0; paragonie/constant_time_encoding v2.4.0 => v2.5.0; phpseclib/phpseclib 3.0.10 => 3.0.14).
* Upgrade guzzlehttp/psr7 2.0.0 => 2.2.1 (security).

= 3.3.0 =
* Add LDAP connection test feature (under LDAP settings).
* Update translatable strings.
* Update French translations. Props @julienlusson!
* Add settings icon to dashboard widget header.
* Better styling in dashboard widget.
* Remove "Local WordPress user" icon from Approved User list (uninformative).
* Small coding standards fixes.

= 3.2.2 =
* Fix PHP warning when anonymous users browse a restricted site.
* Only load authorizer-public.js when necessary (when site is configured so only logged in users can view the site, current user does not have access, and anonymous users should be shown a message). Props @flim0 for the catch!

= 3.2.1 =
* Fix generic OAuth2 connector unable to create username from email. Props @abnerjacobsen for the [bug report](https://github.com/uhm-coe/authorizer/issues/106)!
* Redirect to home page after logging in if using custom login url via the WPS Hide Login plugin. Props @wixaw for the [report](https://github.com/uhm-coe/authorizer/issues/103).

= 3.2.0 =
* Tested up to WordPress 5.8.
* Authorizer now requires PHP 7.2.5 or higher to support its dependencies. See: [this](https://wordpress.org/about/requirements/) and [this](https://www.php.net/supported-versions.php) if you are running an outdated version of PHP.
* Fix for PHP versions below 7.3 (`array_key_last()` is not available for older PHP versions and was added in the last update). Props @ianchan-1 for reporting the issue!
* Update dependencies (apereo/phpcas 1.3.9 => 1.4.0; components/jquery 3.5.1 => 3.6.0; firebase/php-jwt v5.3.0 => v5.4.0; google/auth v1.16.0 => v1.18.0; google/apiclient v2.9.2 => v2.11.0; google/apiclient-services v0.201.0 => v0.213.0; google/auth v1.15.1 => v1.17.0; guzzlehttp/guzzle 6.5.5 => 7.3.0; guzzlehttp/psr7 1.8.2 => 2.0.0; monolog/monolog 1.26.1 => 2.3.4; paragonie/random_compat v2.0.20 => v9.99.100; phpseclib/phpseclib 2.0.32 => 3.0.10).
* Add LDAP Search Filter to plugin settings. Props @hbjusa for the [pull request](https://github.com/uhm-coe/authorizer/pull/102)!
* Add [authorizer_login_form] shortcode. Props @shredderwoods and @hilfans for the suggestions!

= 3.1.2 =
* Fix PHP warnings about uninitialized oauth2_hosteddomain option.

= 3.1.1 =
* Update French translations. Props @julienlusson!
* Note: the next minor version of Authorizer, 3.2, will drop support for PHP 5.6 in order to stay current with phpCAS releases, which now require a minimum of PHP 7.0.

= 3.1.0 =
* Note: the next minor version of Authorizer, 3.2, will drop support for PHP 5.6 in order to stay current with phpCAS releases, which now require a minimum of PHP 7.0.
* Update phpCAS dependency from 1.3.8 to 1.3.9.
* Allow restricting OAuth2 logins to a specific domain (of the email address of users authenticating).
* Update oauth2-azure dependency from 2.0.0 to 2.0.1.
* Update Google APIs Client Library for PHP dependency from 2.8.3 to 2.9.2.
* Update Google PHP API Client Services dependency from 0.156 to 0.201.0.
* Update dependencies of dependencies (firebase/php-jwt 5.2.0 => 5.3.0; google/auth 1.14.3 => 1.15.1; guzzlehttp/promises 1.4.0 => 1.4.1; guzzlehttp/psr7 1.7.0 => 1.8.2
monolog/monolog 1.26.0 => 1.26.1; paragonie/random_compat 2.0.19 => 2.0.20; phpseclib/phpseclib 2.0.31 => 2.0.32; psr/log 1.1.3 => 1.1.4).
* Update translatable strings.


= 3.0.10 =
* Sync role to approved list if edited via bulk action on All Users page. Props @lukeislucas for discovering that edge case!
* Remove unused params in sanitize_user_list().

= 3.0.9 =
* Update phpseclib 2.0.30 => 2.0.31 (CVE-2021-30130).

= 3.0.8 =
* Fix misplaced "This setting is overridden by a multisite option" in subsite settings within a multisite (caused by change in wp-admin core styles).
* Link to appropriate tab in multisite settings when clicking "This setting is overridden by a multisite option."
* Fix for warnings setting first/last name on new pending user.
* Use [standardized WordPress 5.7 admin colors](https://make.wordpress.org/core/2021/02/23/standardization-of-wp-admin-colors-in-wordpress-5-7/).

= 3.0.7 =
* Fix jQuery deprecation notices in WordPress 5.7.
* Tested up to WordPress 5.7.

= 3.0.6 =
* Restore PHP 5.6 compatibility.

= 3.0.5 =
* Fix REST API access restriction (allow app passwords introduced in WordPress 5.6).

= 3.0.4 =
* PHP 8 compatibility.
* Fix warnings about uninitialized oauth2 options.
* Update Google API PHP Client from 2.8.1 to 2.8.3 (composer update google/apiclient).
* Update Google API PHP Client Services from 0.152 to 0.156 (composer update google/apiclient-services).
* Update composer dependencies (monolog 2.1.1 => 2.2.0; phpseclib 2.0.29 => 2.0.30).

= 3.0.3 =
* Fix php errors causing authorizer.js and some vendor assets not to load on network admin. Props @julienlusson for finding this bug!

= 3.0.2 =
* Add tenant-specific configuration option to Microsoft Azure oauth2 provider.

= 3.0.1 =
* Add Microsoft Azure oauth2 provider.
* Updated French translations. Props @julienlusson for the [pull request](https://github.com/uhm-coe/authorizer/pull/96)!

= 3.0.0 =
* Authenticate with more providers via OAuth2. Let us [know](https://github.com/uhm-coe/authorizer/issues) if you have any troubles integrating your OAuth2 provider.
* Add filter `authorizer_oauth2_generic_authorization_parameters` for targeting the specifics of generic oauth2 providers. Provide an array with options, such as `array( 'scope' => 'user:email' )`, to customize your generic oauth2 provider.
* Add filter `authorizer_oauth2_generic_authenticated_email` for manually inspecting the results returned from the oauth2 provider to find the resource owner's email to give to WordPress for the authenticated user. Use this for oauth2 providers that release email addresses in nonstandard places.
* Fix first/last names not getting updated for admins on a CAS or LDAP login.
* Fix PHP warning if invalid login attempt settings are empty (also prevent the “Authorizer lockout triggered for 0 seconds on user after the 0th invalid attempt” simple history log message).
* Fix update usermeta button disappearing in Approved Users list after clicking it.
* Fix serialization of usermeta in Approved Users list for unregistered users.
* Remove bootstrap dependency (replace glyphicons with WordPress dashicons).
* Update translatable strings.
* Update phpCAS from 1.3.6 to 1.3.8.
* Update Google API PHP Client from 2.7.1 to 2.8.1.

= 2.10.0 =
* Update google-api-php-client from v2.2.4 to v2.7.1. Note: extra Google Services have been removed from the vendor library to support hosts that don't like the large vendor library (12,659 files were removed). If you have any problems with your Google sign-ins, please downgrade to 2.9.14 and open a support request!

= 2.9.14 =
* Add `authorizer_additional_ldap_attributes_to_retrieve` filter hook to specify an array of other LDAP attributes to fetch. Props @schtiefel for the [pull request](https://github.com/uhm-coe/authorizer/pull/94)!
* Fix W3C validator errors related to type="text/javascript" in script tags.
* Support ACF Select fields with optgroups in custom usermeta list.
* Better row styling on dashboard widget.
* Add option to update first and last names from CAS/LDAP only if they are empty.
* Don’t print Authorizer help items outside of Authorizer Settings page.
* Log a lockout if we hit the configured limit (via Simple History plugin).
* Fix PHP notice when adding a new user via Dashboard > Users > Add New.
* Tested up to WordPress 5.5.1.

= 2.9.13 =
* Successfully tested on WordPress 5.4.
* Fix warnings about missing variable after last update.
* Update translations. Props @julienlusson for the [pull request](https://github.com/uhm-coe/authorizer/pull/92)!

= 2.9.12 =
* Add feature to disable WordPress logins (only allow logins from configured external services).
* Fix for compatibility issue with User Switching plugin introduced in 2.9.11. Props @ocager for the [report](https://github.com/uhm-coe/authorizer/issues/91)!
* Fix for Sign in button styling on small screen sizes.

= 2.9.11 =
* Fix for CAS logout issue introduced in WordPress 5.3. Props @jespersundstrom for the [report](https://wordpress.org/support/topic/logout-does-not-work-2/)!
* Fix for Active Directory LDAP connections using the domain root as the search base. Props @aszele for the [report and testing](https://wordpress.org/support/topic/unable-to-authenticate-against-active-directory/)!
* Fix hiding WordPress logins in WordPress 5.3. Props @ubercow for the [report](https://wordpress.org/support/topic/hide-wordpress-logins/)!
* Fix Approved User list spacing with multisite and local users.
* Update translations. Props @julienlusson for the [pull request](https://github.com/uhm-coe/authorizer/pull/87)!

= 2.9.10 =
* Fix for some LDAP URIs failing validation check; this should address some users unable to connect after upgrading to version 2.9.9. Props @MamoulianDelacroix for the [report](https://github.com/uhm-coe/authorizer/issues/86)!

= 2.9.9 =
* Allow multiple (failover) LDAP hosts. Props @basildane for the [suggestion](https://github.com/uhm-coe/authorizer/issues/85)!
* Update translations.

= 2.9.8 =
* Allow emails for LDAP logins. Props @jthomae1 for the [suggestion](https://wordpress.org/support/topic/ldap-login-wordpress-docker/)!
* Fix for pending users unable to log out of external service.
* Update styles in Authorizer Settings for WordPress 5.3.
* Better styles in Authorizer Settings for mobile screen sizes.

= 2.9.7 =
* Failsafe for restricting Google Logins to specific domain(s).

= 2.9.6 =
* Fix edge case where another plugin (e.g., Simple Calendar) has already required google-api-php-client v1.
* Use setHostedDomain() included in google-api-php-client v2.

= 2.9.5 =
* Move google-api-php-client due to svn delete issues on deploy.

= 2.9.4 =
* Update google-api-php-client library to v2.2.4 to fix issues with OAuth calls. Props @sieumeo for notifying us about the change!

= 2.9.3 =
* Fix uncaught CAS exception triggering the new Fatal Error Recovery system (email to admins) in WordPress 5.2.
* Fix spacing on Authorizer Settings page.
* Update screenshots.

= 2.9.2 =
* Fix for broken translations in 2.9.0. Props @julienlusson for the pull request!
* Updated French translations. Props @julienlusson for the pull request!

= 2.9.1 =
* Fix for conflict with other plugins including the Google API PHP Client (e.g., Simple Calendar).

= 2.9.0 =
* Major code refactor to make the codebase easier to manage. Authorizer now requires PHP 5.3 or later.
* Fix for edge case with new unapproved users and stale session IDs. Props @vib94 for the pull request!

= 2.8.8 =
* Add missing database migration for new option added in last version.

= 2.8.7 =
* Allow CAS servers to link to WordPress accounts via username instead of email (less secure, but supports more uncommon server configurations). Props @mrn55 for the suggestion!
* Clarify that new local WordPress users get emailed an activation link, not a password.
* Update French translations. Props @julienlusson for the updates!
* Update translatable strings.
* Use the WordPress certificate bundle at /wp-includes/certificates/ca-bundle.crt instead of our own. Props @julienlusson for leading us there!
* Fix for PHP warning in edge case where user isn't allowed to log in.
* Fix pager button styles in Approved User list.
* Fix multisite approved users showing on a site with "override multisite options" enabled.
* Fix for Chrome autofilling the new Blocked User field with saved login email.

= 2.8.6 =
* Feature: Specify a domain wildcard (e.g., “@example.com”) in the block list to block all emails from that domain. Props @olhirt for the feature request!

= 2.8.5 =
* Update phpCAS library from 1.3.5 to 1.3.6. PHP 7.2 users running CAS are now fully supported. Props @julienlusson for the pull request!

= 2.8.4 =
* Fix when inviting existing users to a blog in multisite and setting a role with a display name that doesn't match the role name. Props @julienlusson for finding the bug!

= 2.8.3 =
* Fix for using wp-cli to activate the plugin (broke in 2.8.0). Props @timkite for the discovery!
* Fix for network-activating authorizer via wp-cli.

= 2.8.2 =
* Revert overly strict querystring sanitization (caused CAS login problems in servers that don’t encode forward slashes as %2F in querystring values). Props @anamba for the report and bug testing!

= 2.8.1 =
* Force asset reload (coding standards changed the formatting of a lot of js and css assets).

= 2.8.0 =
* Add authorizer_ldap_search_filter filter (for customizing the LDAP search filter to further restrict LDAP logins). Props @jesus33c for the idea!
* Add authorizer_user_register action. Props @pablo-tapia for the suggestion!
* Allow CAS servers behind redirected URLs. Props @cwhunt for the code!
* Check CAS server reachability by testing serviceValidate endpoint. Props @cwhunt for the code!
* Allow "No role for this site" as a default role for new users. Props @julienlusson for the pull request!
* Update French translations. Props @julienlusson for the pull request!
* Update code to follow WordPress coding standards (php, css, js). Props @michaeldfoley for fixing a bug with our overzealous sanitization!
* Update cacert.pem.
* Fix bug with paging on network approved user list.
* Note: this version requires WordPress 4.4 or later.

= 2.7.2 =
* Fix Approved User list sort when set to Date approved / Descending (was still showing as ascending).
* Support multiple LDAP search bases. Props @jmutsaerts for the feature request.

= 2.7.1 =
* Compatibility fix for PHP < 5.5. Props @klausdk for the report!
* Additional fix for role not getting set when adding an existing user to a site in multisite. Props @julienlusson for the fix!

= 2.7.0 =
* Feature: Approve multiple users at once (by pasting their email addresses into the new approved user field, separated by newlines, spaces, commas, or semicolons).
* Feature: Paging, sorting, and searching in the Approved User list for sites with many users (finally!).
* Update LDAP TLS option for clarity. Props @Scriptkiddi for the pull request!
* Support deprecated multisite constant BLOGID_CURRENT_SITE in addition to BLOG_ID_CURRENT_SITE. Props @er2576 for tracking that down!
* Fix for CAS logouts not working in some situations (remove CAS isAuthenticated() check before CAS logout).
* Fix for updating approved list entry when an email address change is made on the WordPress user profile page in a multisite environment.
* Fix for role not getting set when creating and adding a new user to a blog in multisite. Props @julienlusson for the report and @pkarjala for the fix!

= 2.6.23 =
* Added ability to disable the dashboard widget (useful on sites with many users until paged user lists are implemented).
* Fix for the multisite option override link always going to the External Services tab.
* Fix for hide/show of Login Access options when certain options are selected.

= 2.6.22 =
* Fix for regression showing certain private posts. Props @InvisibleMass for finding the bug!
* Fix for users without the php-mbstring extension installed.
* Update jQuery multi-select plugin from 0.9.8 to 0.9.12.
* Fix for bug in syncing user roles during login. Props @dsusco for the pull request!

= 2.6.21 =
* Fix broken logins caused by regression on previous fix for multivalued email attribute

= 2.6.20 =
* Fix for issue with incorrect parsing of an array of email addresses to be converted to lowercase.
* Fix for nonce cookie issue on google logins where cookie was being sent after headers, resulting in an error message.

= 2.6.19 =
* Fix for issue with case sensitivity checks on user emails affecting role assignments, user deletions, and user updates in Authorizer.  All existing uppercase emails in Authorizer will migrate to lowercase as users log in.  Thank you again to @mmcglynn for continued extensive help in testing.
* Update CAS server connection check to accept 300 response codes as valid presence of a CAS server.  It is the administrator's duty to ensure that a redirect on their CAS url is acceptable.

= 2.6.18 =
* Fix for issue with approved list roles not updating correctly when changed using the authorizer_custom_role hook.  Thank you to @mmcglynn for extensive help in testing.
* Fix for issue with removing user's roles when removing them from a multisite WordPress install.

= 2.6.17 =
* Fix for approved list roles not updating if changed on the fly in authorizer_custom_role hook.
* Update phpCAS from 1.3.4 to 1.3.5. See [changelog](https://github.com/Jasig/phpCAS/blob/master/docs/ChangeLog).

= 2.6.16 =
* Fix: Remove user's role when removing them from the approved list. This is a security feature, in case a removed user is presumed deleted from the site. Since Authorizer does not delete users (to avoid the issue of reassigning or deleting that user’s content), removing their role removes all capabilities from the site until they are re-added to the approved list.

= 2.6.15 =
* Fix for duplicate users in approved list (users added via authorizer_automatically_approve_login filter were re-added to approved list each time they logged in).

= 2.6.14 =
* Move nonce cookie creation to the first time it is needed (for Google logins). Props @emsearcy for the pull request!

= 2.6.13 =
* Respect redirect_to param on CAS logout (if param exists). Props @dgoldber for finding that!

= 2.6.12 =
* Better detection of fuzzy permalink matches for private pages. Applies if site is restricted but 404 pages are marked as public; if this was the case, anonymous visitors to malformed permalinks (e.g., “example.com/sample page” or “example.com/sample%20page” instead of “example.com/sample-page”) were able to see the restricted page. Props @6hogan for finding that!

= 2.6.11 =
* Fix for CAS logins redirecting to the redirect_to param of wp-login.php.
* Fix for redirect after CAS logout on some CAS servers requiring whitelisted services (add a trailing slash to the logout service param).

= 2.6.10 =
* Allow multiple whitelisted domains under Google Hosted Domain. Props Michael K. for the suggestion!
* Drop php-mcrypt library dependency (use openssl library instead since mcrypt is deprecated as of PHP 7.1).
* Fix for some CAS servers redirecting to improper WordPress destination. Props @asithade for the [pull request](https://github.com/uhm-coe/authorizer/pull/29)!
* Fix for mixed-case LDAP attribute names (first name, last name, email) not being recognized because ldap_get_entries() returns attirbute names in lowercase. Props @yatesconsulting for the [report](https://github.com/uhm-coe/authorizer/issues/27)!
* Fix for immediate CAS redirect hook firing after content was sent to browser, triggering a PHP warning if output buffering isn't enabled on the web server. Props @steven1350 for reporting the bug!

= 2.6.9 =
* Fix for LDAP logins failing if the user password contained a single quote, double quote, or a backslash. Props @alxbr for the research!

= 2.6.8 =
* Fix for edge case where a network approved user wouldn't be allowed to visit wp-admin on a site they had not been added to yet.
* Fix for quotation marks in LDAP password causing LDAP bind to fail.
* Fix for issues with marking translated (via WPML) categories public. Props @mafoti for the pull request!
* Fix for placeholder text for plugin option fields being mistaken for actual values. Props @pkarjala for the pull request!
* Fix for blocked flag in usermeta not getting removed when unblocking a user.
* Feature: Add filter to inspect CAS attributes and automatically approve a user based on any values there. Example:
```
/**
 * Filter whether to automatically approve the currently logging in user
 * based on any of their user attributes.
 *
 * @param bool  $automatically_approve_login
 *   Whether to automatically approve the currently logging in user.
 * @param array $user_data User data returned from external service.
 */
function approve_all_faculty_logins( $automatically_approve_login, $user_data ) {
  // Automatically approve logins for all faculty members.
  if (
    isset( $user_data['cas_attributes']['eduPersonAffiliation'] ) &&
    'faculty' === $user_data['cas_attributes']['eduPersonAffiliation']
  ) {
    $automatically_approve_login = true;
  }
  return $automatically_approve_login;
}
add_filter( 'authorizer_automatically_approve_login', 'approve_all_faculty_logins', 10, 2 );
```

= 2.6.7 =
* Support LDAP URI in hostname field (e.g., ldaps://ldap.example.edu:636). Props @timkite for your contribution!
* Update translatable strings.
* Simplify CAS login routine.

= 2.6.6 =
* Fix for mixed line endings in phpCAS library, causing warnings when running PHP Compatibility Checker plugin. Props @wpgirl369/@eshannon3 for the pull request!
* Fix: Never block access to super admins (or admins in single site mode). Props @eizzumdm and @nreljin!
* Add user to network approved list when they are granted super admin privileges on the Edit User screen outside of Authorizer. Remove user from network approved list when this is revoked (and readd them to the approved list on any site they are currently a member of).
* Fix for notification emails sent to all site users if plugin wasn't correctly activated.
* Handle CAS servers that return an email address in response to phpCAS::getUser()

= 2.6.5 =
* Use wp_remote_get() instead of curl to check CAS server availability. php-curl is no longer a dependency.
* Fix for error introduced in last version with cacert.pem updating.

= 2.6.4 =
* Use wp_safe_remote_get() instead of file_get_contents() to update cacert.pem. Props @kriswme2!
* Fix error message shown when login form is first shown and LDAP is enabled. Props @akompanas!
* Fix for lengthy timeout if ldap_start_tls() fails when connecting to an LDAP server. Props @TJuberg!
* Fix a bug preventing first-time login of an approved user when a WordPress user already existed with the same username (but a different email address).
* Remove the spinner overlay when logging in via Google (user could accidentally close the Google sign-in popup, and the spinner prevented them from reopening it by clicking on the "Sign In with Google" button).
* Clean up plugin files (rename 'inc' directory to 'vendor').
* Fix for CAS version option being selectable when it's been multisite overridden.
* Fix for missing translatable string (anonymous access message in bootstrap dismissible alert).
* Show all roles in all sites on the Approved Users role dropdown in network admin.
* Make sure role is updated on all sites when approving a new multisite user that already exists in WordPress.

= 2.6.3 =
* Feature: Add user to authorizer approved list when added from the Users screen.
* Feature: In multisite, add approved user to all approved sites on first login.
* Feature: Sync role and email address in approved list when changed elsewhere.
* Feature: Add super admins to network approved list on plugin activation.
* Feature: Allow "no role for this site" selection for user roles.
* Fix for existing WordPress user logging in: make sure they are in the approved list.
* Fix for local (WordPress) authentication not respecting the blocked list.
* Fix for whitespace and "mailto:" in emails (trim when clicking approve button).
* Fix for external=wordpress safety login not working if option to immediately redirect to CAS is enabled.
* Fix for deprecation warning in WordPress 4.6: wp_get_sites().
* Fix for deprecation warning in WordPress 4.6: wp_new_user_notification().
* Fix for multisite users not being removed from pending lists.
* Improve code efficiency.

= 2.6.2 =
* Revert LDAP/CAS email domain guessing logic (some existing users rely on the old method to determine email address domains). If email domain or CAS/LDAP attribute containing email address is not specified in Authorizer options, guess that email domain is the last two components of the CAS/LDAP host when splitting by periods (e.g., authn.example.com would return an email domain of example.com).

= 2.6.1 =
* Tested up to WordPress 4.6.1.
* Update cacert.pem file.

= 2.6.0 =
* Tested up to WordPress 4.6.
* Feature: Add method for constructing email address for CAS/LDAP servers that don't return an email attribute. Simply enter @yourdomain.edu into the mail attribute field to have email addresses be constructed as username@yourdomain.edu.
* Fix: Updates to cacerts.pem for CAS servers now works for WordPress installs behind a proxy. Props dchambel! https://github.com/uhm-coe/authorizer/pull/13
* Feature: Allow restricting Google logins to a single Google Apps hosted domain (e.g., mycollege.edu).
* Update google-api-php-client from 1.0.5-beta to 1.1.5.
* Fix for REST API integration: Authorizer will now deny read/view access via the REST API if the site is private and the user is not authenticated. Other REST API access is unaffected by Authorizer, and is managed by the REST API authentication schema (cookie, oauth, or basic authentication). See [http://v2.wp-api.org/guide/authentication/](http://v2.wp-api.org/guide/authentication/) for details.
* Fix: Warn if php_openssl.dll is not installed on Windows servers (cannot update cacert.pem if it's missing).
* Fix for mcrypt key length error in php 5.6 and higher.
* Fix for broken newlines in notification emails (also update translations).
* Feature: Customize user roles based on CAS or LDAP attributes. Example:
```
/**
 * Filter the default role of the currently logging in user based on any of
 * their user attributes.
 *
 * @param string $default_role Default role of the currently logging in user.
 * @param array $user_data     User data returned from external service.
 */
function my_authorizer_custom_role( $default_role, $user_data ) {
  // Allow library guests to log in via CAS, but only grant them 'subscriber' role.
  if (
    isset( $user_data['cas_attributes']['eduPersonPrimaryAffiliation'] ) &&
    'library-walk-in' === $user_data['cas_attributes']['eduPersonPrimaryAffiliation']
  ) {
    $default_role = 'subscriber';
  }
  return $default_role;
}
add_filter( 'authorizer_custom_role', 'my_authorizer_custom_role', 10, 2 );
```

= 2.5.1 =
* Updated Spanish translations. Props @elarequi.
* Fix: Include translatable strings found in javascript files.
* Fix: Force lowercase emails from LDAP. Props @akompanas.
* Fix: Set some LDAP defaults likely to be the same on all installs: ldap_port, ldap_attr_username.
* Fix: Construct LDAP default email domain from LDAP search base, not from host (helps to differentiate between subdomain installs and domains with country codes).

= 2.5.0 =
* Translations: Props to @elarequi for wrapping text strings in the translation functions and for providing Spanish translations.
	- Fichero authorizer.php: Se preparan todas las cadenas necesarias, para hacerlas traducibles.
	- Se crea el directorio /languages, con los ficheros de traducción.
* Translations: Props @jojaba for providing French translations.
* Feature: Allow 404 pages to be shown publicly on restricted sites.
* Feature: Add filter to inspect CAS attributes and deny access based on any values there. Props @jojaba for the suggestion. Example:
```
/**
 * Filter whether to block the currently logging in user based on any of their
 * user attributes.
 *
 * @param bool  $allow_login Whether to block the currently logging in user.
 * @param array $user_data   User data returned from external service.
 */
function check_cas_attributes( $allow_login, $user_data ) {
  // Block access to CAS logins from library guests.
  if (
    isset( $user_data['cas_attributes']['eduPersonPrimaryAffiliation'] ) &&
    'library-walk-in' === $user_data['cas_attributes']['eduPersonPrimaryAffiliation']
  ) {
    $allow_login = false;
  }
  return $allow_login;
}
add_filter( 'authorizer_allow_login', 'check_cas_attributes', 10, 2 );
```

* Feature: Add action for inspecting attributes returned from CAS.
* Fix: Users deleted in WordPress will be removed from Authorizer lists. Props @jojaba for catching that.
* Fix: Some plugin options were getting reset when switching between multisite and single site modes. Props @jojaba for finding it.
* Fix: Save button in multisite options was unavailable when disabling multisite override.
* Cleaned up code complexity. Props @mackensen for the pull requests.

= 2.4.0 =
* Feature: Add option to log into CAS automatically (only if no other external service is configured, and only if WordPress logins are hidden). Props @manakuke for the idea!
* Feature: Option to configure older CAS server versions (SAML_VERSION_1_1, CAS_VERSION_3_0, CAS_VERSION_2_0, CAS_VERSION_1_0). Props @autredr for the suggestion and helping debug!
* Fix: Better CAS server availability checking. Props @autredr for the code!
* Documentation: readme.txt now includes the URL to access WordPress logins if they've been disabled.
* Update phpCAS from 1.3.3 to 1.3.4. See [changelog](https://github.com/Jasig/phpCAS/blob/master/docs/ChangeLog).
* Fix for [WordPress REST API (Version 2)](https://wordpress.org/plugins/rest-api/) bypassing Authorizer restricted access. Props @nurbson for the report.

= 2.3.12 =
* The username of new LDAP users will be the value of the attribute specified in "LDAP attribute containing username" instead of the portion of their email address before the @ symbol.

= 2.3.11 =
* Fix for issue with LDAP logins created in the last update. Props @ebraux for the [report](https://wordpress.org/support/topic/ldap-external-stopped-working-since-updating-to-2410)!

= 2.3.10 =
* Handle multiple email addresses registered to a single CAS login (if any are blocked, the user is blocked; otherwise if any are approved, the user is approved).
* Better error reporting on CAS errors.

= 2.3.9 =
* Fix for conflict with [WordPress REST API (Version 2)](https://wordpress.org/plugins/rest-api/) plugin. Props @nurbson for the report.

= 2.3.8 =
* Fix for a fringe case where WordPress users removed from the approved list weren't blocked from accessing a site restricted to approved users.

= 2.3.7 =
* Feature: Show number of users in pending, approved, and blocked lists on Authorizer options page. Props @manakuke for the idea!

= 2.3.6 =
* Feature: Allow anonymous LDAP binds.
* Fix: Concurrency issue with large number of approved users. Props @manakuke.

= 2.3.5 =
* Feature: Allow individual sites in a network/multisite install to override Authorizer's multisite settings and be configured independently.

= 2.3.4 =
* Quick fix: Remove user lists from post data when saving options (fixes an issue with hitting apache/php post size limits when 5000+ approved users exist).

= 2.3.3 =
* Fix: disappearing usermeta box if server is unreachable.
* Update documentation with supported CAS versions.
* Feature: Allow posts to be marked as public on restricted access sites.
* Feature: Allow categories to be marked as public on restricted access sites.

= 2.3.2 =
* Feature: Add the ability to specify which CAS or LDAP attribute contains the user's email address. Useful for organizations that use an ID or something other than an email to authenticate.
* Feature: You can now choose an ACF field to show next to users in the approved list. It will show a dropdown with the available values if the field type is select, and an input[text] otherwise.
* Fix: Preapproved users' usermeta or ACF values get saved and applied when they log in for the first time.
* Fix: ACF5 and ACF4 fields are now listed as options for the usermeta field.

= 2.3.1 =
* Fix: Skip SSL check when checking if a CAS server is reachable.
* Fix: Pressing enter on Access List form elements now does the right thing.
* Feature: Update first and last names from CAS or LDAP attributes.

= 2.3.0 =
* Fix: Site admins in a network can only access authorizer if the following option is enabled in Network Settings: "Allow site administrators to add new users to their site via the "Users → Add New" page." Props @aargh-a-knot.
* Fix: Block user button wasn't correctly moving a user from the approved list to the blocked list.
* Fix: Settings link in plugins list now correctly goes to the Authorizer page if it is shown in the top level menu.
* Enhancement: New icon for authorizer in the plugin directory.
* Enhancement: images have been optimized with ImageOptim.
* Enhancement: Banner in multisite options aligns better when update notifications are present.
* Enhancement: Checkbox and radio option labels are now clickable in authorizer options.
* Verified compatibility with WordPress 4.3.1.

= 2.2.4 =
* fix: only run cas or google logout routines if the current user was authenticated by one of those services
* Thu Apr 16, 2015

= 2.2.3 =
* 2.2.3: fix for multisite function being called on non-multisite installs (prevented plugin installation)
* Thu Apr 16, 2015

= 2.2 =
* 2.2.0: Urgent fix for assets folder (deploy script missed it)
* 2.2.1: readme fix
* 2.2.2: asset fix
* Wed Apr 1, 2015

= 2.1 =
* Updates and bug fixes.
* Wed Apr 1, 2015

= 2.0 =
* First public release.
* Tue Jun 3, 2014

= 1.6 =
* Allow multiple external services to be enabled at once.
* Mon May 26, 2014

= 1.5 =
* Add Google Logins support
* Thu May 22, 2014

= 1.1 =
* Rename to Authorizer
* Add LDAP support
* Wed Mar 12, 2014

= 1.0 =
* First stable release.
* Wed Aug 14, 2013

= 0.2 =
* Switch to CAS instead of LDAP/Sakai.
* Thu Jul 11, 2013

= 0.1 =
* Initial development build.
* Wed Apr 10, 2013
