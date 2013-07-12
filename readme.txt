=== CAS Admission ===
Contributors: figureone
Tags: cas, authentication, authorization, access, education
Requires at least: 3.0.1
Tested up to: 3.5.2
Stable tag: trunk
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

CAS Admission restricts access to students enrolled in university courses, using CAS for authentication and a whitelist of users with permission to access the site.

== Description ==

*CAS Admission* restricts access to a WordPress site to specific users, typically students enrolled in a university course. It replaces the default WordPress login/authorization system with one relying on a CAS server. Further, it maintains a course roster that it can use to restrict access to only students enrolled in a specific course. This course roster can be populated with usernames by an administrator, or an adminstrator can approve individuals from a log of prior CAS login attempts.

*CAS Admission* requires the following:

* **CAS server** (plugin needs the URL)

*CAS Admission* provides the following options:

* **Authentication**: Local (no CAS); Local first, then CAS; CAS-only (except for admins)
* **Access**: Everyone (all have access); University members (all local and all CAS); Specific users (all local and specific CAS)

== Installation ==

1. Upload the `cas-admission` directory to the `/wp-content/plugins/` directory
1. Activate the plugin through the 'Plugins' menu in WordPress
1. Specify your server details in the 'Settings' menu in WordPress

== Frequently Asked Questions ==

= Where is this plugin used? =

The [University of Hawai'i][uh], which provides authentication for student, faculty, and staff members via CAS.

[uh]: http://hawaii.edu/

== Screenshots ==

1. Options screen.

== Changelog ==

= 1.0 =
* First stable release.

= 0.1 =
* Initial development build.
* Thu Jul 11, 2013

== Upgrade Notice ==

= 1.0 =
Upgrade now to get the latest features.
