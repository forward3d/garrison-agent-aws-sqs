module Garrison
  module Checks
    class CheckEncryption < Check

      def settings
        self.source ||= 'aws-sqs'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'sqs' },
          { key: 'aws-account', value: AwsHelper.whoami }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          queues = AwsHelper.list_sqs_queues(region, ["KmsMasterKeyId"])
          not_encrypted = queues.select { |q| q["KmsMasterKeyId"].nil? }

          not_encrypted.each do |queue|
            alert(
              name: 'Encryption Violation',
              target: queue["QueueArn"],
              detail: 'KmsMasterKeyId: nil',
              finding: queue.to_h.to_json,
              finding_id: "aws-sqs-#{queue["QueueArn"]}-encryption",
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/sqs/home?region=#{region}#queue-browser:selected=#{queue["QueueUrl"]};noRefresh=true;prefix="
                }
              ],
              key_values: [
                {
                  key: 'aws-region',
                  value: region
                }
              ]
            )
          end
        end
      end

    end
  end
end
