require "net/http"
require "mixlib/archive"
require "berkshelf/ssl_policies"
require "retryable"
require "mixlib/archive"

module Berkshelf
  class Downloader
    extend Forwardable

    class << self
      # @param [String] target
      #   file path to the tar.gz archive on disk
      # @param [String] destination
      #   file path to extract the contents of the target to
      #
      # @return [String]
      def unpack(target, destination)
        if is_gzip_file(target) || is_tar_file(target)
          Mixlib::Archive.new(target).extract(destination)
        else
          raise Berkshelf::UnknownCompressionType.new(target, destination)
        end

        destination
      end

      # @param [String] version
      #
      # @return [String]
      def uri_escape_version(version)
        version.to_s.tr(".", "_")
      end

      # @param [String] uri
      #
      # @return [String]
      def version_from_uri(uri)
        File.basename(uri.to_s).tr("_", ".")
      end

      private

      def is_gzip_file(path)
        # You cannot write "\x1F\x8B" because the default encoding of
        # ruby >= 1.9.3 is UTF-8 and 8B is an invalid in UTF-8.
        IO.binread(path, 2) == [0x1F, 0x8B].pack("C*")
      end

      def is_tar_file(path)
        IO.binread(path, 8, 257).to_s == "ustar\x0000"
      end
    end

    attr_reader :berksfile

    # @return [String]
    attr_reader :api_uri
    # @return [Integer]
    #   how many retries to attempt on HTTP requests
    attr_reader :retries
    # @return [Float]
    #   time to wait between retries
    attr_reader :retry_interval
    # @return [Berkshelf::RidleyCompat]
    attr_reader :connection

    def_delegators :berksfile, :sources

    V1_API = "https://supermarket.chef.io".freeze

    V1_API_BASE_PATH = "/api/v1/cookbooks".freeze

    # @param [Berkshelf::Berksfile] berksfile
    # @param [String] uri (CommunityREST::V1_API)
    #   location of community site to connect to
    # @option options [Integer] :retries (5)
    #   retry requests on 5XX failures
    # @option options [Float] :retry_interval (0.5)
    #   how often we should pause between retries
    def initialize(berksfile, uri = V1_API, options = {})
      @berksfile = berksfile
      options = options.dup
      options         = { retries: 5, retry_interval: 0.5, ssl: Berkshelf::Config.instance.ssl }.merge(options)
      @api_uri        = uri
      options[:server_url] = uri
      @retries        = options.delete(:retries)
      @retry_interval = options.delete(:retry_interval)

      @connection = Berkshelf::RidleyCompatJSON.new(options)
    end

    def ssl_policy
      @ssl_policy ||= SSLPolicy.new
    end

    # Download the given Berkshelf::Dependency. If the optional block is given,
    # the temporary path to the cookbook is yielded and automatically deleted
    # when the block returns. If no block is given, it is the responsibility of
    # the caller to remove the tmpdir.
    #
    # @param [String] name
    # @param [String] version
    #
    # @option options [String] :path
    #
    # @raise [CookbookNotFound]
    #
    # @return [String]
    def download(*args, &block)
      # options are ignored
      # options = args.last.is_a?(Hash) ? args.pop : Hash.new
      dependency, version = args

      sources.each do |source|
        if ( result = try_download(source, dependency, version) )
          if block_given?
            value = yield result
            FileUtils.rm_rf(result)
            return value
          end

          return result
        end
      end

      raise CookbookNotFound.new(dependency, version, "in any of the sources")
    end

    # @param [Berkshelf::Source] source
    # @param [String] name
    # @param [String] version
    #
    # @return [String]
    def try_download(source, name, version)
      unless ( remote_cookbook = source.cookbook(name, version) )
        return nil
      end

      case remote_cookbook.location_type
      when :opscode, :supermarket
        options = { ssl: source.options[:ssl] }
        if source.type == :artifactory
          options[:headers] = { "X-Jfrog-Art-Api" => source.options[:api_key] }
        end

        # Allow Berkshelf install to function if a relative url exists in location_path
        path = URI.parse(remote_cookbook.location_path).absolute? ? remote_cookbook.location_path : "#{source.uri_string}#{remote_cookbook.location_path}"

        do_download(source, name, version, path)
      when :chef_server
        tmp_dir      = Dir.mktmpdir
        unpack_dir   = Pathname.new(tmp_dir) + "#{name}-#{version}"
        # @todo Dynamically get credentials for remote_cookbook.location_path
        credentials = {
          server_url: remote_cookbook.location_path,
          client_name: source.options[:client_name] || Berkshelf::Config.instance.chef.node_name,
          client_key: source.options[:client_key] || Berkshelf::Config.instance.chef.client_key,
          ssl: source.options[:ssl],
        }
        RidleyCompat.new_client(credentials) do |conn|
          cookbook = Chef::CookbookVersion.load(name, version)
          manifest = cookbook.cookbook_manifest
          manifest.by_parent_directory.each do |segment, files|
            files.each do |segment_file|
              dest = File.join(unpack_dir, segment_file["path"].gsub("/", File::SEPARATOR))
              FileUtils.mkdir_p(File.dirname(dest))
              tempfile = conn.streaming_request(segment_file["url"])
              FileUtils.mv(tempfile.path, dest)
            end
          end
        end
        unpack_dir
      when :github
        require "octokit"

        tmp_dir      = Dir.mktmpdir
        archive_path = File.join(tmp_dir, "#{name}-#{version}.tar.gz")
        unpack_dir   = File.join(tmp_dir, "#{name}-#{version}")

        # Find the correct github connection options for this specific cookbook.
        cookbook_uri = URI.parse(remote_cookbook.location_path)
        if cookbook_uri.host == "github.com"
          options = Berkshelf::Config.instance.github.detect { |opts| opts["web_endpoint"].nil? }
          options = {} if options.nil?
        else
          options = Berkshelf::Config.instance.github.detect { |opts| opts["web_endpoint"] == "#{cookbook_uri.scheme}://#{cookbook_uri.host}" }
          raise ConfigurationError.new "Missing github endpoint configuration for #{cookbook_uri.scheme}://#{cookbook_uri.host}" if options.nil?
        end

        github_client = Octokit::Client.new(
          access_token: options["access_token"],
          api_endpoint: options["api_endpoint"], web_endpoint: options["web_endpoint"],
          connection_options: { ssl: { verify: options["ssl_verify"].nil? ? true : options["ssl_verify"] } }
        )

        begin
          url = URI(github_client.archive_link(cookbook_uri.path.gsub(/^\//, ""), ref: "v#{version}"))
        rescue Octokit::Unauthorized
          return nil
        end

        # We use Net::HTTP.new and then get here, because Net::HTTP.get does not support proxy settings.
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = url.scheme == "https"
        http.verify_mode = (options["ssl_verify"].nil? || options["ssl_verify"]) ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
        resp = http.get(url.request_uri)
        return nil unless resp.is_a?(Net::HTTPSuccess)
        open(archive_path, "wb") { |file| file.write(resp.body) }

        Mixlib::Archive.new(archive_path).extract(unpack_dir)

        # we need to figure out where the cookbook is located in the archive. This is because the directory name
        # pattern is not cosistant between private and public github repositories
        cookbook_directory = Dir.entries(unpack_dir).select do |f|
          (! f.start_with?(".")) && (Pathname.new(File.join(unpack_dir, f)).cookbook?)
        end[0]

        File.join(unpack_dir, cookbook_directory)
      when :uri
        require "open-uri"

        tmp_dir      = Dir.mktmpdir
        archive_path = Pathname.new(tmp_dir) + "#{name}-#{version}.tar.gz"
        unpack_dir   = Pathname.new(tmp_dir) + "#{name}-#{version}"

        url = remote_cookbook.location_path
        open(url, "rb") do |remote_file|
          archive_path.open("wb") { |local_file| local_file.write remote_file.read }
        end

        Mixlib::Archive.new(archive_path).extract(unpack_dir)

        # The top level directory is inconsistant. So we unpack it and
        # use the only directory created in the unpack_dir.
        cookbook_directory = unpack_dir.entries.select do |filename|
          (! filename.to_s.start_with?(".")) && (unpack_dir + filename).cookbook?
        end.first

        (unpack_dir + cookbook_directory).to_s
      when :gitlab
        tmp_dir      = Dir.mktmpdir
        archive_path = Pathname.new(tmp_dir) + "#{name}-#{version}.tar.gz"
        unpack_dir   = Pathname.new(tmp_dir) + "#{name}-#{version}"

        # Find the correct gitlab connection options for this specific cookbook.
        cookbook_uri = URI.parse(remote_cookbook.location_path)
        if cookbook_uri.host
          options = Berkshelf::Config.instance.gitlab.detect { |opts| opts["web_endpoint"] == "#{cookbook_uri.scheme}://#{cookbook_uri.host}" }
          raise ConfigurationError.new "Missing github endpoint configuration for #{cookbook_uri.scheme}://#{cookbook_uri.host}" if options.nil?
        end

        connection ||= Faraday.new(url: options["web_endpoint"]) do |faraday|
          faraday.headers[:accept] = "application/x-tar"
          faraday.response :logger, @logger unless @logger.nil?
          faraday.adapter  Faraday.default_adapter # make requests with Net::HTTP
        end

        resp = connection.get(cookbook_uri.request_uri + "&private_token=" + options["private_token"])
        return nil unless resp.status == 200
        open(archive_path, "wb") { |file| file.write(resp.body) }

        Mixlib::Archive.new(archive_path).extract(unpack_dir)

        # The top level directory is inconsistant. So we unpack it and
        # use the only directory created in the unpack_dir.
        cookbook_directory = unpack_dir.entries.select do |filename|
          (! filename.to_s.start_with?(".")) && (unpack_dir + filename).cookbook?
        end.first

        (unpack_dir + cookbook_directory).to_s
      when :file_store
        tmp_dir = Dir.mktmpdir
        FileUtils.cp_r(remote_cookbook.location_path, tmp_dir)
        File.join(tmp_dir, name)
      else
        raise "unknown location type #{remote_cookbook.location_type}"
      end
    rescue CookbookNotFound
      nil
    end

    # Download and extract target cookbook archive to the local file system,
    # returning its filepath.
    #
    # @param [String] name
    #   the name of the cookbook
    # @param [String] version
    #   the targeted version of the cookbook
    #
    # @return [String, nil]
    #   cookbook filepath, or nil if archive does not contain a cookbook
    def do_download(name, version)
      archive = stream(find(name, version)["file"])
      scratch = Dir.mktmpdir
      extracted = self.class.unpack(archive.path, scratch)

      if File.cookbook?(extracted)
        extracted
      else
        Dir.glob("#{extracted}/*").find do |dir|
          File.cookbook?(dir)
        end
      end
    ensure
      archive.unlink unless archive.nil?
    end

    def find(name, version)
      body = connection.get("cookbooks/#{name}/versions/#{self.class.uri_escape_version(version)}")

      # Artifactory responds with a 200 and blank body for unknown cookbooks.
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'") if body.nil?

      body
    rescue CookbookNotFound
      raise
    rescue Berkshelf::APIClient::ServiceNotFound
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'")
    rescue
      raise CommunitySiteError.new(api_uri, "'#{name}' (#{version})")
    end

    # Returns the latest version of the cookbook and its download link.
    #
    # @return [String]
    def latest_version(name)
      body = connection.get("cookbooks/#{name}")

      # Artifactory responds with a 200 and blank body for unknown cookbooks.
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'") if body.nil?

      self.class.version_from_uri body["latest_version"]
    rescue Berkshelf::APIClient::ServiceNotFound
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'")
    rescue
      raise CommunitySiteError.new(api_uri, "the latest version of '#{name}'")
    end

    # @param [String] name
    #
    # @return [Array]
    def versions(name)
      body = connection.get("cookbooks/#{name}")

      # Artifactory responds with a 200 and blank body for unknown cookbooks.
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'") if body.nil?

      body["versions"].collect do |version_uri|
        self.class.version_from_uri(version_uri)
      end

    rescue Berkshelf::APIClient::ServiceNotFound
      raise CookbookNotFound.new(name, nil, "at `#{api_uri}'")
    rescue
      raise CommunitySiteError.new(api_uri, "versions of '#{name}'")
    end

    # @param [String] name
    # @param [String, Semverse::Constraint] constraint
    #
    # @return [String]
    def satisfy(name, constraint)
      Semverse::Constraint.satisfy_best(constraint, versions(name)).to_s
    rescue Semverse::NoSolutionError
      nil
    end

    # Stream the response body of a remote URL to a file on the local file system
    #
    # @param [String] target
    #   a URL to stream the response body from
    #
    # @return [Tempfile]
    def stream(target)
      local = Tempfile.new("community-rest-stream")
      local.binmode
      Retryable.retryable(tries: retries, on: Berkshelf::APIClientError, sleep: retry_interval) do
        connection.streaming_request(target, {}, local)
      end
    ensure
      local.close(false) unless local.nil?
    end
  end
end
