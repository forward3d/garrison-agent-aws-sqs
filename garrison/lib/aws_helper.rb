module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= Aws::STS::Client.new(region: 'us-east-1').get_caller_identity.account
    end

    def self.all_regions
      Aws::Partitions.partition('aws').service('SQS').regions
    end

    def self.list_sqs_queues(region, attributes)
      if ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN']
        role_credentials = Aws::AssumeRoleCredentials.new(
          client: Aws::STS::Client.new(region: region),
          role_arn: ENV['AWS_ASSUME_ROLE_CREDENTIALS_ARN'],
          role_session_name: 'garrison-agent-sqs'
        )

        sqs = Aws::SQS::Client.new(credentials: role_credentials, region: region, logger: Logging, log_level: :debug)
      else
        sqs = Aws::SQS::Client.new(region: region, logger: Logging, log_level: :debug)
      end

      queue_urls = sqs.list_queues["queue_urls"]
      attrs = ["QueueArn"] + attributes
      queue_urls.map! do |queue_url|
        queue = sqs.get_queue_attributes(queue_url: queue_url, attribute_names: attrs).attributes
        { "QueueUrl" => queue_url }.merge(queue)
      end
    rescue Aws::SQS::Errors::OptInRequired => e
      Logging.warn "#{region} - #{e.message}"
      return []
    rescue Aws::SQS::Errors::InvalidClientTokenId => e
      Logging.warn "#{region} - #{e.message}"
      return []
    end

  end
end
