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
				'data:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				'data://text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				'data//:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				'data/:/text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				' data:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				'da ta:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				'Data:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+',
				"da\nta:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+",
				"da\rta:text/html;base64,PHNjcmlwdD5hbGVydCgnZXZpbCcpPC9zY3JpcHQ+",
			].each do |evil_url|
				sanitize_url(evil_url, :replace_evil_with => 'replaced').should == 'replaced'
			end
		end
		
		context 'with :protocols whitelist' do
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
					sanitize_url(evil_url, :protocols => ['http'], :replace_evil_with => 'replaced')
				end
			end
			
			it 'allows anything on the list' do
				[
					'http://example.com',
					'https://example.com'
				].each do |good_url|
					sanitize_url(good_url, :protocols => ['http', 'https']).should == good_url
				end
			end
		end
		
		it 'prepends http:// if no protocol is given' do
			sanitize_url('www.example.com').should == 'http://www.example.com'
		end
		
		it 'fixes common mistakes in the protocol' do
			sanitize_url('http//www.example.com').should == 'http://www.example.com'
			sanitize_url('http/www.example.com').should == 'http://www.example.com'
			sanitize_url('http:www.example.com').should == 'http://www.example.com'
			sanitize_url('http:/www.example.com').should == 'http://www.example.com'
			sanitize_url('http//:www.example.com').should == 'http://www.example.com'
		end
		
		it 'does not try to fix broken protocols after the start of the string' do
			sanitize_url('http://example.com/http/foo').should == 'http://example.com/http/foo'
		end
		
		it 'does not prepend an extra http:// if a valid protocol is given' do
			sanitize_url('http://www.example.com').should == 'http://www.example.com'
			sanitize_url('https://www.example.com').should == 'https://www.example.com'
			sanitize_url('ftp://www.example.com').should == 'ftp://www.example.com'
		end
	end
end
