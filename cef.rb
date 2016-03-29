# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This example filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an example.
class LogStash::Filters::CEF < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #   example {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "cef"
  
  # Replace the message with this value.
  # The field to perform CEF parsing on
  #
  # For example, to process the `not_the_message` field:
  # [source,ruby]
  #     filter { cef { source => "not_the_message" } }
  config :source, :validate => :string, :default => "message"
  
  # The name of the container to put all of the key-value pairs into.
  #
  # If this setting is omitted, fields will be written to the root of the
  # event, as individual fields.
  #
  # For example, to place all keys into the event field kv:
  # [source,ruby]
  #     filter { cef { target => "cef" } }
  config :target, :validate => :string, :default => "cef_ext"

  public
  def register
    # Add instance variables 
	# Do I have to put something here???
  end # def register

  public
  def filter(event)
	if @source
	  message = event[@source]

	  event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], message = message.split /(?<!\\)[\|]/

	  # Try and parse out the syslog header if there is one
	  if event['cef_version'].include? ' '
	    event['syslog'], unused, event['cef_version'] = event['cef_version'].rpartition(' ')
	  end
	  # Get rid of the CEF bit in the version
	  version = event['cef_version'].sub /^CEF:/, ''
	  event['cef_version'] = version

	  # Strip any whitespace from the beginning and end of the message
	  if not message.nil? and message.include? '='
		message = message.strip

		# If the last KVP has no value, add an empty string, this prevents hash errors below
		if message.end_with?("=")
		  message=message + ' '
		end

	    # Now parse the key value pairs into it
	    extensions = {}
	    message = message.split(/ ([\w\.]+)=/)
	    key, value = message.shift.split('=', 2)
	    extensions[key] = value

	    Hash[*message].each{ |k, v| extensions[k] = v }

	    # And save the new has as the extensions
	    event[@target] = extensions
	  end

	  # Replace the event message with our message as configured in the
	  # config file.
	  #event["message"] = @source
    end

	# filter_matched should go in the last line of our successful code
	filter_matched(event)
  end # def filter
end # class LogStash::Filters::cef