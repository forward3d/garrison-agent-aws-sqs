module Garrison
  module Checks
    class CheckRedrive < Check

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
          queues = AwsHelper.list_sqs_queues(region, ["RedrivePolicy"])

          dead_letter_queue_arns = queues.select { |q| q["RedrivePolicy"] }.map { |q| JSON.parse(q["RedrivePolicy"])["deadLetterTargetArn"] }
          no_redrive = queues.reject { |q| dead_letter_queue_arns.include?(q["QueueArn"]) }.select { |q| q["RedrivePolicy"].nil? }

          no_redrive.each do |queue|
            alert(
              name: 'Redrive Policy Violation',
              target: queue["QueueArn"],
              detail: "SQS queue has no DLQ and isn't acting as one",
              finding: queue.to_h.to_json,
              finding_id: "aws-sqs-#{queue["QueueArn"]}-redrive",
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
