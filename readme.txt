=== Authorizer ===
Contributors: figureone, the_magician, pkarjala, aargh-a-knot, elarequi, jojaba
Tags: cas, ldap, google, google plus, login, authentication, authorization, access, education, limit login attempts, oauth
Requires at least: 3.8
Tested up to: 4.7.4
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).

== Description ==

*Authorizer* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as Google, CAS, or LDAP. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

View or contribute to the plugin source on Github: [https://github.com/uhm-coe/authorizer](https://github.com/uhm-coe/authorizer)

*Authorizer* requires the following:

* **CAS server** (2.x, 3.x, 4.x, or 5.x) or **LDAP server** (plugin needs the URL)
* PHP extensions: php-ldap, php-curl, php-dom

*Authorizer* provides the following options:

* **Authentication**: WordPress accounts; Google accounts; CAS accounts; LDAP accounts
* **Login Access**: All authenticated users (all local and all external can log in); Only specific users (all local and approved external users can log in)
* **View Access**: Everyone (open access); Only logged in users
* **Limit Login Attempts**: Progressively increase the amount of time required between invalid login attempts.

== Installation ==

1. Upload the `authorizer` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Specify your server details in the 'Settings' menu in WordPress

== Frequently Asked Questions ==

= Help! I've disabled WordPress logins, my external logins (Google/CAS/LDAP) aren't working, and now I can't get back in! =

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
* Fix: Set some LDAP defaults likely to be the same on all installs : ldap_port, ldap_attr_username.
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

== Upgrade Notice ==

= 1.0 =
Upgrade now to get the latest features.
