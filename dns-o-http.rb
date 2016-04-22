#!/usr/bin/env ruby

require 'ipaddr'
require 'json'
require 'net/http'

def name2labels(name)
  name.split(".").map { |label|
    [ label.length, label ].pack("Ca*")
  }.join("") + "\0"
end

def name_to_character_string(name)
  [ name.length, name ].pack("Ca*")
end

module DNS
  class Query
    def initialize bytes
      @bytes = bytes
      @qname, @qtype = parse_question
    end

    attr_reader :bytes, :qname, :qtype

    def parse_question
      labels = []
      i = 12
      loop do
        len = @bytes[i].unpack("C")[0]
        i += 1
        break if len == 0
        labels << @bytes[i, len]
        i += len
      end
      qname = labels.join(".")
      qtype = @bytes[i, 2].unpack("n")[0]

      [ qname, qtype ]  # who wants QCLASS?
    end
  end

  class Response
    def initialize query, json
      @json = json

      qid, qword = query.bytes.unpack("nn")

      rword =  0x8000                # QR
      rword |= 0x7000 & qword        # Opcode
      rword |= 0x0400 & qword        # AA
      rword |= 0x0200 if @json["TC"]
      rword |= 0x0100 if @json["RD"]
      rword |= 0x0080 if @json["RA"]
      rword |= 0x0020 if @json["AD"]
      rword |= 0x0010 if @json["CD"]
      rword |= 0x000f & @json["Status"]

      qdcount = @json["Question"].length
      ancount = (@json["Answer"] || []).length

      bytes = [ qid, rword, qdcount, ancount, 0, 0 ].pack("nnnnnn")
      bytes += make_question(bytes, @json["Question"])
      bytes += make_answer(bytes, @json["Answer"])

      @bytes = bytes
    end

    attr_reader :bytes

    def make_question(bytes, question)
      s = ""
      question.each { |q|
        s += [ name2labels(q["name"]), q["type"], 1 ].pack("a*nn")
      }
      s
    end

    def make_answer(bytes, answer)
      return "" unless answer
      s = ""
      answer.each { |a|
        rdata = ""
        case a["type"]
        when 1  # A
          rdata = IPAddr.new(a["data"]).hton
        when 5  # CNAME
          rdata = name2labels(a["data"])
        when 12 # PTR
          rdata = name2labels(a["data"])
        when 16 # TXT
          rdata = name_to_character_string(a["data"])
        when 28 # AAAA
          rdata = IPAddr.new(a["data"]).hton
        else
          raise "type #{a["type"]} is not supported"
        end
        s += name2labels(a["name"])
        s += [ a["type"], 1, a["TTL"], rdata.length ].pack("nnNn")
        s += rdata
      }
      s
    end
  end

  class HTTPS
    def initialize
      @https = Net::HTTP.new("dns.google.com", 443)
      @https.use_ssl = true
    end

    def query(name, type)
      @https.start { |http|
        puts "query: /resolve?name=#{name}&type=#{type}"
        response = http.get("/resolve?name=#{name}&type=#{type}")
        unless response.is_a? Net::HTTPSuccess
          raise "HTTP error: #{response.inspect}"
        end

        JSON.parse(response.body)
      }
    end
  end
end

udp = UDPSocket.new
udp.setsockopt(:SOCKET, :REUSEADDR, true)
udp.bind("127.0.0.1", 8053)

dns = DNS::HTTPS.new

loop do
  pkt, src = udp.recvfrom(5000)
  query = DNS::Query.new pkt
  json = dns.query(query.qname, query.qtype)
  p json
  r = DNS::Response.new(query, json)
  p r.bytes

  sa = Socket.sockaddr_in(src[1], src[3])
  udp.send(r.bytes, 0, sa)
end

dns.query "www.kame.net"
