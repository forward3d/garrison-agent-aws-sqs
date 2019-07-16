module Garrison
  module Checks
    class CheckDeadLetterQueueRetention < Check

      def settings
        self.source ||= 'aws-sqs'
        self.severity ||= 'high'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
        self.options[:threshold] ||= 1_209_600
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
          queues = AwsHelper.list_sqs_queues(region, ["RedrivePolicy", "MessageRetentionPeriod"])

          dead_letter_queue_arns = queues.select { |q| q["RedrivePolicy"] }.map { |q| JSON.parse(q["RedrivePolicy"])["deadLetterTargetArn"] }
          dead_letter_queues = queues.select { |q| dead_letter_queue_arns.include?(q["QueueArn"]) }
          violations = dead_letter_queues.select { |q| q["MessageRetentionPeriod"].to_i < options[:threshold].to_i }

          violations.each do |queue|
            alert(
              name: 'DLQ Message Retention Violation',
              target: queue["QueueArn"],
              detail: "message_retention_period: #{queue["MessageRetentionPeriod"]} (<#{options[:threshold]})",
              finding: queue.to_h.to_json,
              finding_id: "aws-sqs-#{queue["QueueArn"]}-dlqmessageretention",
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
