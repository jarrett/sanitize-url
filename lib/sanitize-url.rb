module SanitizeUrl
	def sanitize_url(url, options = {})
		raise(ArgumentError, 'options[:protocols] must be an array') if options.has_key?(:protocols) and !options[:protocols].is_a?(Array)
		options = {
			:replace_evil_with => '',
			:protocols => ['http', 'https', 'ftp', 'ftps', 'mailto', 'svn', 'svn+ssh', 'git']
		}.merge(options)
		# Fix broken protocols
		protocol = nil
		url = url.sub(/^(([a-zA-Z\s]+)[\/:]+)/) do
			protocol = $2.downcase
			protocol + '://'
		end
		# If we didn't find anything resembling a protocol, then we need to prepend one.
		# We just use http, since it's the most likely suspect and there's no other way to guess
		unless protocol
			protocol = 'http'
			url = 'http://' + url
		end
		if options[:protocols].include?(protocol)
			url
		else
			options[:replace_evil_with]
		end
	end
end