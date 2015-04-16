=== Authorizer ===
Contributors: figureone, the_magician, pkarjala
Tags: cas, ldap, google, google plus, login, authentication, authorization, access, education, limit login attempts, oauth
Requires at least: 3.8
Tested up to: 4.1.1
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

Authorizer limits login attempts, restricts access to specified users, and authenticates against external sources (e.g., Google, LDAP, or CAS).

== Description ==

*Authorizer* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It maintains a list of approved users that you can edit to determine who has access. It also replaces the default WordPress login/authorization system with one relying on an external server, such as Google, CAS, or LDAP. Finally, *Authorizer* lets you limit invalid login attempts to prevent bots from compromising your users' accounts.

*Authorizer* requires the following:

* **CAS server** or **LDAP server** (plugin needs the URL)
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
