=== Authorizer ===
Contributors: figureone, the_magician, pkarjala, aargh-a-knot, elarequi, jojaba, slyraskal
Tags: login, authentication, cas, ldap, oauth
Tested up to: 6.6
Stable tag: 3.10.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authorizer limits login attempts, restricts access to specific users, and authenticates against external sources (OAuth2, Google, LDAP, or CAS).

== Description ==

*Authorizer* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as Google, CAS, LDAP, or an OAuth2 provider. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

View or contribute to the plugin source on GitHub: [https://github.com/uhm-coe/authorizer](https://github.com/uhm-coe/authorizer)

*Authorizer* requires the following:

* **CAS server** (2.x, 3.x, 4.x, 5.x, 6.x, or 7.x) or **LDAP server** (plugin needs the URL)
* PHP extensions: php-ldap, php-curl, php-dom

*Authorizer* provides the following options:

* **Authentication**: WordPress accounts; Google accounts; CAS accounts; LDAP accounts; OAuth2 accounts
* **Login Access**: All authenticated users (all local and all external can log in); Only specific users (all local and approved external users can log in)
* **View Access**: Everyone (open access); Only logged in users
* **Limit Login Attempts**: Progressively increase the amount of time required between invalid login attempts.
* **Shortcode**: Use the `[authorizer_login_form]` shortcode to embed a wp_login_form() outside of wp-login.php.

== Installation ==

1. Upload the `authorizer` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Specify your server details in the 'Settings' menu in WordPress

== Frequently Asked Questions ==

= Help! I've disabled WordPress logins, my external logins (Google/CAS/LDAP/OAuth2) aren't working, and now I can't get back in! =

If you add external=wordpress to the wp-login.php URL querystring, you can always get the WordPress login form to reappear. For example, if your site is at [https://www.example.com](https://www.example.com), then the URL would be: [https://www.example.com/wp-login.php?external=wordpress](https://www.example.com/wp-login.php?external=wordpress)

= Where is this plugin used? =

The [University of Hawai'i][uh], which provides authentication for student, faculty, and staff members via a centralized service (CAS or LDAP).

[uh]: http://hawaii.edu/

== Screenshots ==

1. WordPress Login screen with Google Logins and CAS Logins enabled.
2. Authorizer Dashboard Widget.
3. Authorizer Options: Access Lists.
4. Authorizer Options: Login Access.
5. Authorizer Options: Public Access.
6. Authorizer Options: External Service.
7. Authorizer Options: Advanced.
8. Authorizer Network Admin Options (disabled).
9. Authorizer Network Admin Options: Access Lists.
10. Authorizer Network Admin Options: External Service.
11. Authorizer Network Admin Options: Advanced.
12. Authorizer Option overridden by a Network Admin Option.

== Changelog ==

= 3.10.2 =
* Fix for [redirect error on CAS logins](https://github.com/uhm-coe/authorizer/issues/167). Props greg-randall for the pull [request](https://github.com/uhm-coe/authorizer/pull/168)!

= 3.10.1 =
* Hotfix for CAS logins broken if new settings not saved.

= 3.10.0 =
* Allow multiple configured CAS endpoints ([details](https://github.com/uhm-coe/authorizer/issues/14)).
* Allow fetching username and email from custom attributes in OAuth2 (generic) external service.
* Add OAuth2 (generic) options for syncing first and last names from external service.
* Force Google Logins to use FedCM to support upcoming removal of third-party cookies in chromium browsers. Props faeldray for the [report](https://github.com/uhm-coe/authorizer/issues/157)!
* Revert [WPML fix](https://github.com/uhm-coe/authorizer/pull/25) from 2017 for displaying categories in the Private Pages list in the Public Access tab of Authorizer settings. Props tlebars for the [report](https://github.com/uhm-coe/authorizer/issues/153)!
* Update French translations. Props @julienlusson!
* Add $user param to `authorizer_custom_role` hook; can be used to inspect the roles of the logging in user if they already have a WordPress user account.
* Add missing `authorizer_oauth2_azure_authenticated_email` hook (alongside `authorizer_oauth2_generic_authenticated_email` hook).
* Update composer dependencies: guzzlehttp/guzzle (7.9.1 => 7.9.2); phpseclib/phpseclib (3.0.39 => 3.0.42).

= 3.9.1 =
* Fix for global $wp_roles unavailable in some multisite contexts leading to a fatal error.
* Update French translations. Props @julienlusson!

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

= < 3.0.0 =
* [Full changelog available here](https://github.com/uhm-coe/authorizer/blob/master/CHANGELOG.md)

== Upgrade Notice ==

= 3.5.0 =
**Upgrade Notice**: Google Sign-Ins now use the new [Google Identity Services library](https://developers.google.com/identity/gsi/web/guides/migration), which uses a different Sign In button UI and may also include the One Tap prompt. Please test if you use Google Sign-Ins!

= 3.2.0 =
Authorizer now requires PHP 7.2.5 or higher (phpCAS 1.4.0 requirement).

= 1.0 =
Upgrade now to get the latest features.
