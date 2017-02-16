require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe SanitizeUrl do
	include SanitizeUrl
	
	describe '#sanitize_url' do
		it 'replaces JavaScript URLs with options[:replace_evil_with]' do
			urls = [
				'javascript:alert("1");',
				'javascript//:alert("2");',
				'javascript://alert("3");',
				'javascript/:/alert("4");',
				'j a v a script:alert("5");',
				' javascript:alert("6");',
				'JavaScript:alert("7");',
				"java\nscript:alert(\"8\");",
				"java\rscript:alert(\"9\");"
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		it 'replaces data: URLs with options[:replace_evil_with]' do
			urls = [
				'data:text/html;base64,PHNjcmlwdD5hbGVydCgnMScpPC9zY3JpcHQ+',
				'data://text/html;base64,PHNjcmlwdD5hbGVydCgnMicpPC9zY3JpcHQ+',
				'data//:text/html;base64,PHNjcmlwdD5hbGVydCgnMycpPC9zY3JpcHQ+',
				'data/:/text/html;base64,PHNjcmlwdD5hbGVydCgnNCcpPC9zY3JpcHQ+',
				' data:text/html;base64,PHNjcmlwdD5hbGVydCgnNScpPC9zY3JpcHQ+',
				'da ta:text/html;base64,PHNjcmlwdD5hbGVydCgnNicpPC9zY3JpcHQ+',
				'Data:text/html;base64,PHNjcmlwdD5hbGVydCgnNycpPC9zY3JpcHQ+',
				"da\nta:text/html;base64,PHNjcmlwdD5hbGVydCgnOCcpPC9zY3JpcHQ+",
				"da\rta:text/html;base64,PHNjcmlwdD5hbGVydCgnOScpPC9zY3JpcHQ+",
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		context 'with :schemes whitelist' do
			it 'kills anything not on the list' do
				[
					'https://example.com',
					'https:example.com',
					'ftp://example.com',
					'ftp:example.com',
					'data://example.com',
					'data:example.com',
					'javascript://example.com',
					'javascript:example.com',
				].each do |evil_url|
					sanitize_url(evil_url, :schemes => ['http'], :replace_evil_with => 'replaced')
				end
			end
			
			it 'allows anything on the list' do
				[
					'http://example.com',
					'https://example.com'
				].each do |good_url|
					sanitize_url(good_url, :schemes => ['http', 'https']).should == good_url
				end
			end
			
			it 'works with schemes given as symbols' do
				sanitize_url('ftp://example.com', :schemes => [:http, :https], :replace_evil_with => 'replaced').should == 'replaced'
				sanitize_url('ftp://example.com', :schemes => [:http, :https, :ftp]).should == 'ftp://example.com'
			end
		end
		
		it 'prepends http:// if no scheme is given' do
			sanitize_url('www.example.com').should == 'http://www.example.com'
		end
		
		it 'prepends default_scheme option if no scheme is given and defauult_scheme option is set' do
			sanitize_url('www.example.com', :default_scheme => 'https').should == 'https://www.example.com'
		end
		
		it 'replaces evil URLs that are encoded with Unicode numerical character references' do
			[
				'&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#49;&#39;&#41;',
				'&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x27;&#x32;&#x27;&#x29;'
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		it 'replaces evil URLs that are URL-encoded (hex with %)' do
			sanitize_url('%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%22%58%53%53%22%29', :replace_evil_with => 'replaced').should == 'replaced'
		end
		
		it 'does not try to fix broken schemes after the start of the string' do
			sanitize_url('http://example.com/http/foo').should == 'http://example.com/http/foo'
		end
		
		it 'does not prepend an extra http:// if a valid scheme is given' do
			sanitize_url('http://www.example.com').should == 'http://www.example.com'
			sanitize_url('https://www.example.com').should == 'https://www.example.com'
			sanitize_url('ftp://www.example.com').should == 'ftp://www.example.com'
		end
		
		it 'dereferences URL-encoded characters in the scheme' do
			sanitize_url('h%74tp://example.com').should == 'http://example.com'
		end
		
		it 'dereferences decimal numeric character references in the scheme' do
			sanitize_url('h&#116;tp://example.com').should == 'http://example.com'
		end
		
		it 'dereferences hex numeric character references in the scheme' do
			sanitize_url('h&#x74;tp://example.com').should == 'http://example.com'
		end
		
		it 'retains URL-encoded characters in the opaque portion' do
			sanitize_url('http://someone%40gmail.com:password@example.com').should == 'http://someone%40gmail.com:password@example.com'
		end
		
		it 'URL-encodes code points outside ASCII' do
			# Percent-encoding should be in UTF-8 (RFC 3986).
			# http://en.wikipedia.org/wiki/Percent-encoding#Current_standard
			sanitize_url('http://&#1044;').should == 'http://%D0%94'
			sanitize_url('http://&#x0414;').should == 'http://%D0%94'
			sanitize_url("http://\xD0\x94").should == 'http://%D0%94' # UTF-8 version of the same.
		end
		
		it 'replaces URLs without the opaque portion' do
			sanitize_url('http://', :replace_evil_with => 'replaced').should == 'replaced'
			sanitize_url('mailto:', :replace_evil_with => 'replaced').should == 'replaced'
		end
		
		it 'adds the two slashes for known schemes that require it' do
			sanitize_url('http:example.com').should == 'http://example.com'
			sanitize_url('ftp:example.com').should == 'ftp://example.com'
			sanitize_url('svn+ssh:example.com').should == 'svn+ssh://example.com'
		end
		
		it 'does not add slashes for schemes that do not require it' do
			sanitize_url('mailto:someone@example.com').should == 'mailto:someone@example.com'
		end
		
		it 'strips invalid characters from the scheme and then evaluates the scheme according to the normal rules' do
			sanitize_url("ht\xD0\x94tp://example.com").should == 'http://example.com'
			sanitize_url('htt$p://example.com').should == 'http://example.com'
			sanitize_url('j%avascript:alert("XSS")', :replace_evil_with => 'replaced').should == 'replaced'
		end
	end
		
	
	describe '.dereference_numerics' do				
		it 'decodes short-form decimal UTF-8 character references with a semicolon' do
			SanitizeUrl.dereference_numerics('&#106;').should == 'j'
		end
		
		it 'decodes short-form decimal UTF-8 character references without a semicolon' do
			SanitizeUrl.dereference_numerics('&#106').should == 'j'
		end
		
		it 'decodes long-form decimal UTF-8 character references with a semicolon' do
			SanitizeUrl.dereference_numerics('&#0000106;').should == 'j'
		end
		
		it 'decodes long-form decimal UTF-8 character references without a semicolon' do
			SanitizeUrl.dereference_numerics('&#0000106').should == 'j'
		end
		
		it 'decodes hex UTF-8 character references with a semicolon' do
			SanitizeUrl.dereference_numerics('&#x6A;').should == 'j'
		end
		
		it 'decodes hex UTF-8 character references without a semicolon' do
			SanitizeUrl.dereference_numerics('&#x6A').should == 'j'
		end
	end
end
