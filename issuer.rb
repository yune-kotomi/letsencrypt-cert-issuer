require 'openssl'
require 'acme/client'
require 'yaml'
require 'fileutils'

config = YAML.load(open(ARGV[0]).read)
private_key = OpenSSL::PKey::RSA.new(open(config['private_key']))
endpoint = 'https://acme-v01.api.letsencrypt.org/'

config['sites'].each do |site|
  client = Acme::Client.new(:private_key => private_key, :endpoint => endpoint)
  authorization = client.authorize(:domain => site['domain'])

  challenge = authorization.http01
  Dir.chdir(site['wwwroot']) do
    FileUtils.mkdir_p(File.dirname(challenge.filename))
    open(challenge.filename, 'w') {|f| f.puts challenge.file_content }
  end

  challenge.request_verification
  sleep 3

  if challenge.verify_status == 'valid'
    csr = Acme::Client::CertificateRequest.new(:names => [site['domain']])
    certificate = client.new_certificate(csr)

    FileUtils.mkdir_p(File.dirname(site['private']))
    open(site['private'], 'w') {|f| f.puts certificate.request.private_key.to_pem }

    FileUtils.mkdir_p(File.dirname(site['fullchain']))
    open(site['fullchain'], 'w') {|f| f.puts certificate.fullchain_to_pem }
  else
    puts "error! #{site['domain']}"
  end
end
