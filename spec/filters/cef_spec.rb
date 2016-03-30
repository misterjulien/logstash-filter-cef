# encoding: utf-8
require 'spec_helper'
require "logstash/filters/cef"

describe LogStash::Filters::CEF do
  describe "Parse the CEF event" do
    let(:config) do <<-CONFIG
      filter {
        cef {}
      }
    CONFIG
    end

    #sample("message" => "CEF:0|Firewall Vendor|The Product|5.0.0|end|TRAFFIC|1|rt=Mar 28 2016 20:50:38 GMT src=10.11.12.103 cs1Label=Rule cs1=My Rule Here suser=domain\theuser") do
    sample ("CEF:0|Firewall Vendor|The Product|5.0.0|end|TRAFFIC|1|rt=Mar 28 2016 20:50:38 GMT src=10.11.12.103 cs1Label=Rule cs1=My Rule Here suser=domain\theuser") do
      #expect(subject).to include("message")
      expect(subject['cef_version']).to eq('0')
	  expect(subject['cef_vendor']).to eq('Firewall Vendor')
	  expect(subject['cef_product']).to eq('The Product')
	  expect(subject['cef_device_version']).to eq('5.0.0')
	  expect(subject['cef_sigid']).to eq('end')
	  expect(subject['cef_name']).to eq('TRAFFIC')
	  expect(subject['cef_severity']).to eq('1')
	  expect(subject['rt']).to eq('Mar 28 2016 20:50:38 GMT')
	  expect(subject['src']).to eq('10.11.12.103')
	  expect(subject['cs1Label']).to eq('Rule')
	  expect(subject['cs1']).to eq('My Rule Here')
	  expect(subject['suser']).to eq("domain\theuser")  
    end
  end
end
