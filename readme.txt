=== Authorizer ===
Contributors: figureone, the_magician, pkarjala, aargh-a-knot
Tags: cas, ldap, google, google plus, login, authentication, authorization, access, education, limit login attempts, oauth
Requires at least: 3.8
Tested up to: 4.4.1
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).

== Description ==

*Authorizer* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as Google, CAS, or LDAP. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

*Authorizer* requires the following:

* **CAS server** (2.x, 3.x, or 4.x) or **LDAP server** (plugin needs the URL)
* PHP extentions: php5-mcrypt, php5-ldap, php5-curl

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
* Feature:  You can now choose an ACF field to show next to users in the approved list. It will show a dropdown with the available values if the field type is select, and an input[text] otherwise.
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
