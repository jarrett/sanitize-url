sanitize-url
============

This gem provides a module called `SanitizeUrl`, which you can mix-in anywhere you like. It provides a single method: `sanitize_url`, which accepts a URL and returns one with JavaScript removed. It also prepends the `http://` scheme if no valid scheme is found.

Why do you need this? Because attackers can sneak JavaScript into URLs, and some browsers may execute it. Say, for example, you have a web app that lets users post links. If you don't sanitize the URLs, you may have a cross-site-scripting vulnerability on your hands. More commonly, well-intentioned users will type URLs without prepending a protocol. If you render these URLs as-in your links, the browser will interpret them as links within your own site, e.g. `http://your-site.com/www.site-they-linked-to.com`.

Rails mitigates some of the danger by automatically URL-encoding in the `link_to` helper, but this does not solve every problem. For example, it doesn't remove plain old `javascript:alert("xss")`, and URLs with numeric character references come out broken. This gem fixes those and other problems.

Basic Usage
===========

	require 'rubygems'
	require 'sanitize-url'
	
	include SanitizeUrl
	
	sanitize_url('www.example.com')

Advanced
========

This gem uses a whitelist approach, killing any schemes that aren't in the list. This should block `javascript:` and `data:` URLs, both of which can be used for XSS. The default list of allowed schemes is:

	http://
	https://
	ftp://
	ftps://
	mailto://
	svn://
	svn+ssh://
	git://
	mailto:

You can pass in your own whitelist like this:

	sanitize_url('http://example.com', :schemes => ['http', 'https'])

If `sanitize_url` receives a URL with a forbidden scheme, it wipes out the entire URL and returns a blank string. You can override this behavior and have it return a string of your choosing like this:

	sanitize_url('javascript:alert("XSS")', :replace_evil_with => 'my replacement')
	# => 'my replacement'

See the spec/sanitize_url_spec.rb for some examples of the how this gem transforms URLs.

Installation
============

	gem install sanitize-url

If that doesn't work, it's probably because the gem is hosted on Gemcutter, and your computer doesn't know about Gemcutter yet. To fix that:

	gem install gemcutter
	gem tumble

Bug Reports
===========

Since this is a security-related gem, you'll rack up mad karma by reporting a bug. If you find a way to sneak executable JavaScript (or any other form of evil) past the filter, please send me a message on GitHub:

http://github.com/inbox/new/jarrett

For most projects, I prefer that people use GitHub's issue tracker. But given the sensitive nature of security vulnerabilities, I prefer private messages for this one.

== Copyright

Copyright (c) 2010 Jarrett Colby. See LICENSE for details.